#!/usr/bin/env python3
# substitution_solver_fast.py — ULTRA-FINAL VERSION
# Accurate monoalphabetic substitution solver with deterministic final cleanup.
# Simulated annealing + adaptive restarts + exhaustive last-phase sweep.

import math, random, re, time, sys, os
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

alphabet = list("abcdefghijklmnopqrstuvwxyz")


# =========================
#   Helper: Polybius Standardization
# =========================
def polybius_standardize(message):
    message = message.replace(" ", "")
    coords, coord = [], ""
    for i, k in enumerate(message):
        if i % 2 == 0 and coord:
            coords.append(coord)
            coord = ""
        coord += k
    if coord:
        coords.append(coord)
    unique_coords = list(set(coords))
    standardized = ""
    for i in coords:
        standardized += alphabet[unique_coords.index(i)]
    return standardized.upper()


# =========================
#   Environment Helper (Render detection)
# =========================
def _running_on_render():
    """
    Best-effort detection of Render environment.
    We keep this very lightweight and non-invasive.
    """
    env = os.environ
    return any(
        key in env
        for key in (
            "RENDER",
            "RENDER_SERVICE_ID",
            "RENDER_EXTERNAL_HOSTNAME",
            "RENDER_INSTANCE_ID",
        )
    )


# =========================
#   Public API
# =========================
def apply_substitution(text, key_cipher_to_plain):
    """Apply cipher→plain key to text, preserving case and punctuation."""
    out = []
    for ch in text:
        if ch.isalpha():
            up = ch.upper()
            mapped = key_cipher_to_plain.get(up, up)
            out.append(mapped.lower() if ch.islower() else mapped)
        else:
            out.append(ch)
    return "".join(out)


def _find_two_letter_runs(CT_UP, min_run=40):
    """Mask long two-letter-only sequences (e.g., Baconian) from scoring."""
    n = len(CT_UP)
    mask = [False] * n
    binary_sets = [
        set("AB"),
        set("BA"),
        set("EU"),
        set("UE"),
        set("OI"),
        set("IO"),
        set("01"),
        set("XO"),
        set("OX"),
    ]
    i = 0
    while i < n:
        if not CT_UP[i].isalpha():
            i += 1
            continue
        j = i
        while j < n and CT_UP[j].isalpha():
            j += 1
        run = CT_UP[i:j]
        uniq = set(run)
        if len(uniq) == 2 and len(run) >= min_run and any(uniq == s for s in binary_sets):
            for k in range(i, j):
                mask[k] = True
        i = j
    return mask


# =========================
#   Core Solver
# =========================
def substitution_break(
    ciphertext,
    max_restarts=14,
    sa_steps=9000,
    seed=None,
    time_limit_seconds=35,
    threads=None,
    fixed=None,
    verbose=True,
    ignore_twoletter_runs=True,
    min_twoletter_run_len=40,
):
    if seed is not None:
        random.seed(seed)

    # --- Thread selection: Option B ---
    # If caller passes threads explicitly, honour it (>=1).
    # Otherwise:
    #   - On Render: force threads=1
    #   - Local:     threads = min(8, cpu_cores)
    if threads is None:
        if _running_on_render():
            threads_local = 1
        else:
            threads_local = min(8, (os.cpu_count() or 2))
    else:
        threads_local = max(1, threads)

    start_time = time.time()
    AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    A2I = {c: i for i, c in enumerate(AZ)}

    CT = ciphertext
    CT_UP = CT.upper()

    excluded = [False] * len(CT_UP)
    if ignore_twoletter_runs:
        excluded = _find_two_letter_runs(CT_UP, min_run=min_twoletter_run_len)
        if verbose and any(excluded):
            run_len = sum(1 for i, ch in enumerate(CT_UP) if ch.isalpha() and excluded[i])
            print(f"[note] Ignoring ~{run_len} letters inside long two-letter runs.")

    # Clean and map
    L = [A2I[ch] for i, ch in enumerate(CT_UP) if "A" <= ch <= "Z" and not excluded[i]]
    nL = len(L)
    if nL < 8:
        key = _freq_start_key(CT, AZ)
        if fixed:
            _apply_fixed(key, fixed)
        return key, apply_substitution(CT, key)

    # --- English model ---
    CORPUS = """
    IT IS A TRUTH UNIVERSALLY ACKNOWLEDGED THAT A SINGLE MAN IN POSSESSION OF A GOOD FORTUNE
    MUST BE IN WANT OF A WIFE. HOWEVER LITTLE KNOWN THE FEELINGS OR VIEWS OF SUCH A MAN MAY BE
    ON HIS FIRST ENTERING A NEIGHBOURHOOD THIS TRUTH IS SO WELL FIXED IN THE MINDS OF THE
    SURROUNDING FAMILIES THAT HE IS CONSIDERED THE RIGHTFUL PROPERTY OF SOME ONE OR OTHER OF THEIR DAUGHTERS.
    WHEN YOU HAVE ELIMINATED THE IMPOSSIBLE WHATEVER REMAINS HOWEVER IMPROBABLE MUST BE THE TRUTH.
    IN THE BEGINNING GOD CREATED THE HEAVEN AND THE EARTH AND THE EARTH WAS WITHOUT FORM AND VOID AND DARKNESS
    WAS UPON THE FACE OF THE DEEP AND THE SPIRIT OF GOD MOVED UPON THE FACE OF THE WATERS AND GOD SAID LET THERE
    BE LIGHT AND THERE WAS LIGHT.
    WE HOLD THESE TRUTHS TO BE SELF EVIDENT THAT ALL MEN ARE CREATED EQUAL THAT THEY ARE ENDOWED BY THEIR CREATOR
    WITH CERTAIN UNALIENABLE RIGHTS THAT AMONG THESE ARE LIFE LIBERTY AND THE PURSUIT OF HAPPINESS.
    CALL ME ISHMAEL SOME YEARS AGO NEVER MIND HOW LONG PRECISELY HAVING LITTLE OR NO MONEY IN MY PURSE AND NOTHING
    PARTICULAR TO INTEREST ME ON SHORE I THOUGHT I WOULD SAIL ABOUT A LITTLE AND SEE THE WATERY PART OF THE WORLD.
    THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG.
    """
    lp2, _ = _ngram_logprobs_dense(CORPUS, 2, k=0.5)
    lp3, _ = _ngram_logprobs_dense(CORPUS, 3, k=0.5)
    lp4, _ = _ngram_logprobs_dense(CORPUS, 4, k=0.5)

    if nL < 120:
        W4, W3, W2 = 0.7, 0.25, 0.05
    elif nL < 250:
        W4, W3, W2 = 1.0, 0.22, 0.06
    else:
        W4, W3, W2 = 1.2, 0.22, 0.06
    _scale_dense(lp4, W4)
    _scale_dense(lp3, W3)
    _scale_dense(lp2, W2)

    pos_by_c = [[] for _ in range(26)]
    for i, c in enumerate(L):
        pos_by_c[c].append(i)

    def affected_starts_for_pos(j):
        starts = set()
        if nL >= 4:
            for s in range(max(0, j - 3), min(nL - 3, j + 1)):
                starts.add(("q", s))
        if nL >= 3:
            for s in range(max(0, j - 2), min(nL - 2, j + 1)):
                starts.add(("t", s))
        if nL >= 2:
            for s in range(max(0, j - 1), min(nL - 1, j + 1)):
                starts.add(("b", s))
        return starts

    pre_affects = [affected_starts_for_pos(j) for j in range(nL)]

    def new_random_key(rng):
        p = list(range(26))
        rng.shuffle(p)
        return p

    def freq_start_key_list():
        d = _freq_start_key(CT, AZ)
        arr = [0] * 26
        inv = {A2I[c]: A2I[p] for c, p in d.items()}
        for c_idx in range(26):
            arr[c_idx] = inv.get(c_idx, c_idx)
        return arr

    def apply_fixed_list(P):
        if not fixed:
            return
        locked = {A2I[c]: A2I[p] for c, p in fixed.items()}
        for c_idx, p_idx in locked.items():
            P[c_idx] = p_idx

    # --- Scoring ---
    def full_score(P):
        s = 0.0
        if nL >= 4:
            for i in range(nL - 3):
                a, b, c, d = P[L[i]], P[L[i + 1]], P[L[i + 2]], P[L[i + 3]]
                s += lp4[((a * 26 + b) * 26 + c) * 26 + d]
        if nL >= 3:
            for i in range(nL - 2):
                a, b, c = P[L[i]], P[L[i + 1]], P[L[i + 2]]
                s += lp3[(a * 26 + b) * 26 + c]
        if nL >= 2:
            for i in range(nL - 1):
                a, b = P[L[i]], P[L[i + 1]]
                s += lp2[a * 26 + b]
        return s

    def delta_swap(P, a, b):
        affected = set()
        for j in pos_by_c[a]:
            affected |= pre_affects[j]
        for j in pos_by_c[b]:
            affected |= pre_affects[j]
        old_s = new_s = 0.0
        Pa, Pb = P[a], P[b]
        for kind, s in affected:
            if kind == "q":
                x = [P[L[s + k]] for k in range(4)]
                old_s += lp4[((x[0] * 26 + x[1]) * 26 + x[2]) * 26 + x[3]]
                y = [
                    Pb if L[s + k] == a else Pa if L[s + k] == b else x[k]
                    for k in range(4)
                ]
                new_s += lp4[((y[0] * 26 + y[1]) * 26 + y[2]) * 26 + y[3]]
            elif kind == "t":
                x = [P[L[s + k]] for k in range(3)]
                old_s += lp3[(x[0] * 26 + x[1]) * 26 + x[2]]
                y = [
                    Pb if L[s + k] == a else Pa if L[s + k] == b else x[k]
                    for k in range(3)
                ]
                new_s += lp3[(y[0] * 26 + y[1]) * 26 + y[2]]
            else:
                x0, x1 = P[L[s]], P[L[s + 1]]
                old_s += lp2[x0 * 26 + x1]
                y0 = Pb if L[s] == a else Pa if L[s] == b else x0
                y1 = Pb if L[s + 1] == a else Pa if L[s + 1] == b else x1
                new_s += lp2[y0 * 26 + y1]
        return new_s - old_s

    COMMON_WORDS = (
        "the and to of a in that it is was for on with as you at be this have not are but he his they we by from or an "
        "one all their there what so up out if about who get which go me when make can like no just him her said had were "
        "them then some into more time would your now only little very than people could first over after also even because "
        "new where most use work find give long day man woman life"
    ).split()

    def semantic_bonus(text):
        t = text.lower()
        b = 0.0
        for w in COMMON_WORDS:
            b += 0.15 * len(re.findall(rf"\b{re.escape(w)}\b", t))
        b += 0.12 * len(re.findall(r"\b(a|i)\b", t))
        return b

    # --- Single restart ---
    def one_restart(ridx, init_kind):
        rng = random.Random((seed or 0) + 1337 * ridx + hash(init_kind))
        P = freq_start_key_list() if init_kind == "freq" else new_random_key(rng)
        apply_fixed_list(P)
        best = full_score(P)
        T0, T_end = 6.2, 0.32
        stag, stag_limit = 0, 1400
        steps = sa_steps
        reheat_at = steps // 2

        for step in range(1, steps + 1):
            if time.time() - start_time > time_limit_seconds:
                break
            if step % 2000 == 0:
                T0 *= 0.9
            if step == reheat_at:
                T0 *= 0.9
            T = T0 * ((T_end / T0) ** (step / steps))
            a, b = rng.randrange(26), rng.randrange(26)
            if a == b:
                continue
            d = delta_swap(P, a, b)
            if d > 0 or rng.random() < math.exp(d / max(T, 1e-12)):
                P[a], P[b] = P[b], P[a]
                best += d
                stag = 0
            else:
                stag += 1
            if stag >= stag_limit:
                stag = 0
                for _ in range(10):
                    x, y = rng.randrange(26), rng.randrange(26)
                    dd = delta_swap(P, x, y)
                    if dd > 0:
                        P[x], P[y] = P[y], P[x]
                        best += dd

        # Greedy local polish
        improved = True
        while improved and time.time() - start_time < time_limit_seconds:
            improved = False
            # Reduced deterministic cleanup search space (Render-safe ~80% speedup)
            CANDIDATES = list(range(26))
            # Shuffle so we don't always favour same letters
            random.shuffle(CANDIDATES)

            # Only check first 14 letters instead of all 26
            LIMIT = 14

            for a_i in range(LIMIT):
                for b_i in range(a_i + 1, LIMIT):
                    a = CANDIDATES[a_i]
                    b = CANDIDATES[b_i]

                    d = delta_swap(P, a, b)
                    if d > 1e-6:
                        P[a], P[b] = P[b], P[a]
                        improved = True

        # --- Final deterministic cleanup ---
        def total_value(P_):
            kd = {AZ[c]: AZ[P_[c]] for c in range(26)}
            pt = apply_substitution(CT, kd)
            return full_score(P_) + semantic_bonus(pt)

        EPS = 1e-9
        improved = True
        while improved and time.time() - start_time < time_limit_seconds:
            improved = False
            base_val = total_value(P)
            best_gain, best_pair = 0.0, None
            for a in range(26):
                for b in range(a + 1, 26):
                    d_est = delta_swap(P, a, b)
                    P[a], P[b] = P[b], P[a]
                    cand_val = total_value(P)
                    P[a], P[b] = P[b], P[a]
                    gain = cand_val - base_val
                    if gain > best_gain + EPS or (
                        abs(gain - best_gain) <= EPS and d_est > 0
                    ):
                        best_gain, best_pair = gain, (a, b)
            if best_pair and best_gain > EPS:
                a, b = best_pair
                P[a], P[b] = P[b], P[a]
                improved = True

        return P, total_value(P)

    # --- Multi-restart (Render-safe) ---
    jobs = [("freq" if i == 0 else "rand") for i in range(max_restarts)]
    results = []

    if threads_local == 1:
        # Sequential (Render / single-core safe)
        for ridx, kind in enumerate(jobs):
            results.append(one_restart(ridx, kind))
            if verbose:
                sys.stdout.write(f"\r[restart {ridx + 1}/{len(jobs)} done]")
                sys.stdout.flush()
    else:
        # Parallel (local, multi-core)
        with ThreadPoolExecutor(max_workers=threads_local) as exe:
            futs = {
                exe.submit(one_restart, ridx, kind): (ridx, kind)
                for ridx, kind in enumerate(jobs)
            }
            for n, f in enumerate(as_completed(futs), 1):
                results.append(f.result())
                if verbose:
                    sys.stdout.write(f"\r[completed {n}/{len(jobs)} restarts]")
                    sys.stdout.flush()

    if verbose:
        print("")

    bestP, _ = max(results, key=lambda z: z[1])
    key_dict = {AZ[c]: AZ[bestP[c]] for c in range(26)}
    plain = apply_substitution(CT, key_dict)

    if verbose:
        dur = time.time() - start_time
        print(
            f"[done in {dur:.1f}s | restarts={len(jobs)} | threads={threads_local}]"
        )

    return key_dict, plain


# =========================
#   Helpers
# =========================
def _ngram_logprobs_dense(corpus, n, k=0.5):
    AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    A2I = {c: i for i, c in enumerate(AZ)}
    t = re.sub(r"[^A-Z]", "", corpus.upper())
    if len(t) < 8000:
        t = (t * (8000 // max(1, len(t)) + 1))[:8000]
    counts = Counter()
    for i in range(len(t) - n + 1):
        idx = 0
        for j in range(n):
            idx = idx * 26 + A2I[t[i + j]]
        counts[idx] += 1
    total = sum(counts.values())
    vocab = 26**n
    denom = total + k * vocab
    floor = math.log(k / denom)
    arr = [floor] * (26**n)
    for idx, c in counts.items():
        arr[idx] = math.log((c + k) / denom)
    return arr, floor


def _scale_dense(arr, w):
    if abs(w - 1.0) < 1e-12:
        return
    for i in range(len(arr)):
        arr[i] *= w


def _freq_start_key(text, AZ):
    EN = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    t = re.sub(r"[^A-Z]", "", text.upper())
    cnt = Counter(t)
    order = [p[0] for p in cnt.most_common()]
    for a in AZ:
        if a not in order:
            order.append(a)
    return {order[i]: EN[i] for i in range(26)}


def _apply_fixed(key_dict, fixed):
    for c, p in fixed.items():
        key_dict[c] = p


# =========================
#   CLI
# =========================
if __name__ == "__main__":
    print("=== Monoalphabetic Substitution Solver (Ultra-Final) ===")
    cipher = input("> ").strip()
    if not cipher:
        print("No ciphertext provided.")
        sys.exit(0)
    key, plain = substitution_break(
        cipher,
        max_restarts=14,
        sa_steps=9000,
        time_limit_seconds=35,
        seed=42,
        verbose=True,
    )
    print("\n--- Best Guess Plaintext ---")
    print(plain)
    print("\n--- Cipher → Plain Key ---")
    AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    print(" ".join(AZ))
    print(" ".join(key.get(c, "?") for c in AZ))
