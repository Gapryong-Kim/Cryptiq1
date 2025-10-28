#!/usr/bin/env python3
# substitution_solver_fast.py
# Fast + accurate monoalphabetic substitution solver (Windows-safe threading)
# Tuned for ALL ciphertext lengths: adaptive weights, mini-reheats, light polish.
# Robust to mixed ciphers: ignores long two-letter runs (e.g. Baconian) for scoring.

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
#   Public API
# =========================
def apply_substitution(text, key_cipher_to_plain):
    """Apply cipher→plain key to text, preserving non-letters and case."""
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
    """Find long two-letter-only runs (like Baconian) and mask them out."""
    n = len(CT_UP)
    mask = [False] * n
    binary_sets = [set("AB"), set("BA"), set("EU"), set("UE"), set("OI"), set("IO"), set("01"), set("XO"), set("OX")]

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
def substitution_break(ciphertext,
                       max_restarts=14,
                       sa_steps=9000,
                       seed=None,
                       time_limit_seconds=35,
                       threads=None,
                       fixed=None,
                       verbose=True,
                       ignore_twoletter_runs=True,
                       min_twoletter_run_len=40):
    """Adaptive monoalphabetic substitution solver with threaded restarts."""
    if seed is not None:
        random.seed(seed)

    start_time = time.time()
    AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    A2I = {c: i for i, c in enumerate(AZ)}

    # Normalize ciphertext
    CT = ciphertext
    CT_UP = CT.upper()

    excluded = [False] * len(CT_UP)
    if ignore_twoletter_runs:
        excluded = _find_two_letter_runs(CT_UP, min_run=min_twoletter_run_len)
        if verbose and any(excluded):
            run_len = sum(1 for i, ch in enumerate(CT_UP) if ch.isalpha() and excluded[i])
            print(f"[note] Ignoring ~{run_len} letters inside long two-letter runs.")

    letters_idx, kept_pos = [], []
    for idx, ch in enumerate(CT_UP):
        if 'A' <= ch <= 'Z' and not excluded[idx]:
            letters_idx.append(A2I[ch])
            kept_pos.append(idx)

    L = letters_idx
    nL = len(L)

    # Quick fallback
    if nL < 8:
        key = _freq_start_key(CT, AZ)
        if fixed:
            _apply_fixed(key, fixed)
        plain = apply_substitution(CT, key)
        return key, plain

    # --------- English model ---------
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

    # Adaptive weights by ciphertext length
    if nL < 120:
        W4, W3, W2 = 0.7, 0.25, 0.05
    elif nL < 250:
        W4, W3, W2 = 1.0, 0.22, 0.06
    else:
        W4, W3, W2 = 1.20, 0.22, 0.06
    _scale_dense(lp4, W4)
    _scale_dense(lp3, W3)
    _scale_dense(lp2, W2)

    # Precompute structures
    pos_by_c = [[] for _ in range(26)]
    for i, c in enumerate(L):
        pos_by_c[c].append(i)

    def affected_starts_for_pos(j):
        starts = set()
        if nL >= 4:
            for s in (j - 3, j - 2, j - 1, j):
                if 0 <= s <= nL - 4:
                    starts.add(('q', s))
        if nL >= 3:
            for s in (j - 2, j - 1, j):
                if 0 <= s <= nL - 3:
                    starts.add(('t', s))
        if nL >= 2:
            for s in (j - 1, j):
                if 0 <= s <= nL - 2:
                    starts.add(('b', s))
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
        taken = set(locked.values())
        free_plain = [i for i in range(26) if i not in taken]
        seen = set()
        for c_idx in range(26):
            if c_idx in locked:
                seen.add(P[c_idx])
                continue
            if P[c_idx] in seen or P[c_idx] in taken:
                P[c_idx] = free_plain.pop(0)
            seen.add(P[c_idx])

    # Scoring functions
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
            if kind == 'q':
                x0, x1, x2, x3 = P[L[s]], P[L[s + 1]], P[L[s + 2]], P[L[s + 3]]
                old_s += lp4[((x0 * 26 + x1) * 26 + x2) * 26 + x3]
                y0 = Pb if L[s] == a else (Pa if L[s] == b else x0)
                y1 = Pb if L[s + 1] == a else (Pa if L[s + 1] == b else x1)
                y2 = Pb if L[s + 2] == a else (Pa if L[s + 2] == b else x2)
                y3 = Pb if L[s + 3] == a else (Pa if L[s + 3] == b else x3)
                new_s += lp4[((y0 * 26 + y1) * 26 + y2) * 26 + y3]
            elif kind == 't':
                x0, x1, x2 = P[L[s]], P[L[s + 1]], P[L[s + 2]]
                old_s += lp3[(x0 * 26 + x1) * 26 + x2]
                y0 = Pb if L[s] == a else (Pa if L[s] == b else x0)
                y1 = Pb if L[s + 1] == a else (Pa if L[s + 1] == b else x1)
                y2 = Pb if L[s + 2] == a else (Pa if L[s + 2] == b else x2)
                new_s += lp3[(y0 * 26 + y1) * 26 + y2]
            else:
                x0, x1 = P[L[s]], P[L[s + 1]]
                old_s += lp2[x0 * 26 + x1]
                y0 = Pb if L[s] == a else (Pa if L[s] == b else x0)
                y1 = Pb if L[s + 1] == a else (Pa if L[s + 1] == b else x1)
                new_s += lp2[y0 * 26 + y1]
        return new_s - old_s

    COMMON_WORDS = (
        "the and to of a in that it is was for on with as you at be this have not are but he his they we by from or an "
        "one all their there what so up out if about who get which go me when make can like no just him her said had were "
        "them then some into more time would your now only little very than people could first over after also even because "
        "new where most use work find give long day man woman life"
    ).split()
    WORD_BONUS, ONE_LETTER_BONUS = 0.15, 0.12

    def semantic_bonus(plaintext: str) -> float:
        t = plaintext.lower()
        b = 0.0
        for w in COMMON_WORDS:
            b += WORD_BONUS * len(re.findall(rf"\b{re.escape(w)}\b", t))
        b += ONE_LETTER_BONUS * len(re.findall(r"\b(a|i)\b", t))
        return b

    def combined_score(P):
        base = full_score(P)
        key_dict = {AZ[c]: AZ[P[c]] for c in range(26)}
        plain = apply_substitution(CT, key_dict)
        return base + semantic_bonus(plain)

    # Single restart
    def one_restart(ridx, init_kind):
        rng = random.Random((seed or 0) + 1337 * ridx + hash(init_kind))
        P = freq_start_key_list() if init_kind == 'freq' else new_random_key(rng)
        apply_fixed_list(P)

        best = full_score(P)
        T0, T_end = 6.2, 0.32
        stag, stag_limit = 0, 1400
        steps = sa_steps
        reheat_at = steps // 2

        for step in range(1, steps + 1):
            if time.time() - start_time > time_limit_seconds:
                break
            # Mini-reheat every few thousand steps
            if step % 2000 == 0:
                T0 *= 0.9
            if step == reheat_at:
                T0 *= 0.9
            T = T0 * ((T_end / T0) ** (step / steps))
            a, b = rng.randrange(26), rng.randrange(26)
            if a == b:
                continue
            if fixed and (_is_locked_idx(a, fixed, A2I) or _is_locked_idx(b, fixed, A2I)):
                continue
            d = delta_swap(P, a, b)
            if d >= 0 or rng.random() < math.exp(d / max(T, 1e-12)):
                P[a], P[b] = P[b], P[a]
                best += d
                stag = 0
            else:
                stag += 1
            if stag >= stag_limit:
                stag = 0
                for _ in range(14):
                    x, y = rng.randrange(26), rng.randrange(26)
                    if fixed and (_is_locked_idx(x, fixed, A2I) or _is_locked_idx(y, fixed, A2I)):
                        continue
                    dd = delta_swap(P, x, y)
                    if dd > 0:
                        P[x], P[y] = P[y], P[x]
                        best += dd

        # Greedy delta polish
        improved = True
        while improved and (time.time() - start_time) <= time_limit_seconds:
            improved = False
            best_pair = None
            best_impr = 0.0
            for a in range(26):
                for b in range(a + 1, 26):
                    if fixed and (_is_locked_idx(a, fixed, A2I) or _is_locked_idx(b, fixed, A2I)):
                        continue
                    d = delta_swap(P, a, b)
                    if d > best_impr:
                        best_impr, best_pair = d, (a, b)
            if best_pair:
                a, b = best_pair
                P[a], P[b] = P[b], P[a]
                improved = True

        # Final semantic + pattern polish
        curr_score = combined_score(P)
        if nL > 50:
            text_guess = apply_substitution(CT, {AZ[c]: AZ[P[c]] for c in range(26)})
            pattern_bonus = sum(1 for i in range(len(text_guess)-3) if text_guess[i:i+3] == text_guess[i+3:i+6])
            curr_score += pattern_bonus * 0.2

        return P, curr_score

    # Parallel restarts
    jobs = [('freq' if i == 0 else 'rand') for i in range(max_restarts)]
    threads = min(8, (os.cpu_count() or 2)) if threads is None else max(1, threads)

    results = []
    if threads == 1:
        for ridx, kind in enumerate(jobs):
            results.append(one_restart(ridx, kind))
            if verbose:
                sys.stdout.write(f"\r[restart {ridx+1}/{len(jobs)} done]")
                sys.stdout.flush()
    else:
        with ThreadPoolExecutor(max_workers=threads) as exe:
            fut_to_id = {exe.submit(one_restart, ridx, kind): (ridx, kind) for ridx, kind in enumerate(jobs)}
            for n, fut in enumerate(as_completed(fut_to_id), 1):
                results.append(fut.result())
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
        print(f"[done in {dur:.1f}s | restarts={len(jobs)} | threads={threads}]")

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
    vocab = 26 ** n
    denom = total + k * vocab
    floor = math.log(k / denom)
    arr = [floor] * (26 ** n)
    for idx, c in counts.items():
        arr[idx] = math.log((c + k) / denom)
    return arr, floor


def _scale_dense(arr, w):
    if abs(w - 1.0) < 1e-12:
        return
    for i in range(len(arr)):
        arr[i] *= w


def _freq_start_key(text, AZ):
    ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    t = re.sub(r"[^A-Z]", "", text.upper())
    cnt = Counter(t)
    order = [p[0] for p in cnt.most_common()]
    for a in AZ:
        if a not in order:
            order.append(a)
    return {order[i]: ENGLISH_FREQ_ORDER[i] for i in range(26)}


def _apply_fixed(key_dict, fixed):
    for c, p in fixed.items():
        key_dict[c] = p


def _is_locked_idx(c_idx, fixed, A2I):
    return fixed is not None and (list(A2I.keys())[c_idx] in fixed)


# =========================
#   CLI
# =========================
if __name__ == "__main__":
    print("=== Monoalphabetic Substitution Solver (adaptive) ===")
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
        verbose=True
    )

    print("\n--- Best Guess Plaintext ---")
    print(plain)

    print("\n--- Cipher → Plain Key ---")
    AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    print(" ".join(AZ))
    print(" ".join(key.get(c, '?') for c in AZ))
