#!/usr/bin/env python3
# substitution_solver_fast.py — ULTRA-FINAL VERSION (Stronger scoring)
# Accurate monoalphabetic substitution solver with deterministic final cleanup.
# Simulated annealing + adaptive restarts + global pair-swap disambiguation,
# with a beefed-up English scoring model for fewer last-letter mistakes.

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

#!/usr/bin/env python3
# substitution_break_improved.py
#
# Improvements vs your current version:
# 1) Optional external corpus (corpus_path) + much better default fallback corpus.
# 2) Adds an incremental English letter-frequency chi² term DURING SA (big accuracy win).
# 3) Tracks "best-by-combined-score" checkpoints during SA (helps avoid tetragram-only traps).
# 4) Keeps your fast delta n-gram swap + your deterministic cleanup + global pair disambiguation.
# 5) Fixed constraints respected without breaking permutation validity.

import math, random, re, time, sys, os
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed


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
    """
    Mask long 2-symbol-only sequences (letters OR digits) from scoring.
    """
    n = len(CT_UP)
    mask = [False] * n

    binary_sets = {
        frozenset(("A", "B")),
        frozenset(("E", "U")),
        frozenset(("O", "I")),
        frozenset(("0", "1")),
        frozenset(("X", "O")),
    }

    i = 0
    while i < n:
        if not (CT_UP[i].isalpha() or CT_UP[i].isdigit()):
            i += 1
            continue

        j = i
        while j < n and (CT_UP[j].isalpha() or CT_UP[j].isdigit()):
            j += 1

        run = CT_UP[i:j]
        uniq = frozenset(run)

        if len(uniq) == 2 and len(run) >= min_run and uniq in binary_sets:
            for k in range(i, j):
                mask[k] = True

        i = j

    return mask


# =========================
#   Core Solver
# =========================
def substitution_break(
    ciphertext,
    max_restarts=18,
    sa_steps=14000,
    seed=None,
    time_limit_seconds=35,
    threads=None,
    fixed=None,
    verbose=True,
    ignore_twoletter_runs=True,
    min_twoletter_run_len=40,
    # NEW:
    corpus_path=None,          # optional external corpus text file
    corpus_text=None,          # optional corpus string passed in
    chi_weight=3.0,            # SA letter-frequency pressure (1.5..6.0)
    checkpoint_every=450,      # SA checkpoint cadence
):
    if seed is not None:
        random.seed(seed)

    # --- Thread selection ---
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
            run_len = sum(
                1
                for i, ch in enumerate(CT_UP)
                if (ch.isalpha() or ch.isdigit()) and excluded[i]
            )
            print(f"[note] Ignoring ~{run_len} symbols inside long two-letter runs.")

    # Clean and map
    L = [A2I[ch] for i, ch in enumerate(CT_UP) if "A" <= ch <= "Z" and not excluded[i]]
    nL = len(L)
    if nL < 8:
        key = _freq_start_key(CT, AZ)
        if fixed:
            _apply_fixed(key, fixed)
        return key, apply_substitution(CT, key)

    # =========================
    #   English model: n-grams
    # =========================
    # Better default corpus (public-domain-ish style snippets; still small but much better than the tiny one)
    DEFAULT_CORPUS = """
    IN THE BEGINNING GOD CREATED THE HEAVEN AND THE EARTH AND THE EARTH WAS WITHOUT FORM AND VOID
    AND DARKNESS WAS UPON THE FACE OF THE DEEP AND THE SPIRIT MOVED UPON THE FACE OF THE WATERS.
    WE HOLD THESE TRUTHS TO BE SELF EVIDENT THAT ALL MEN ARE CREATED EQUAL AND ENDOWED WITH CERTAIN
    UNALIENABLE RIGHTS AMONG THESE ARE LIFE LIBERTY AND THE PURSUIT OF HAPPINESS.
    WHEN YOU HAVE ELIMINATED THE IMPOSSIBLE WHATEVER REMAINS HOWEVER IMPROBABLE MUST BE THE TRUTH.
    IT WAS THE BEST OF TIMES IT WAS THE WORST OF TIMES IT WAS THE AGE OF WISDOM IT WAS THE AGE OF FOOLISHNESS.
    CALL ME ISHMAEL SOME YEARS AGO NEVER MIND HOW LONG PRECISELY HAVING LITTLE OR NO MONEY IN MY PURSE.
    I AM AN INVISIBLE MAN. NO I AM NOT A SPOOK LIKE THOSE WHO HAUNT EDGAR ALLAN POE.
    THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG.
    THERE ARE MANY THINGS IN THIS WORLD THAT A MAN MAY UNDERSTAND AND MANY THAT HE MUST FEEL.
    I HAVE OFTEN WONDERED AT THE BREADTH OF THE SEA AND AT THE GREATNESS OF THE SKY.
    """

    corpus = None
    if corpus_text and isinstance(corpus_text, str) and corpus_text.strip():
        corpus = corpus_text
    elif corpus_path:
        try:
            with open(corpus_path, "r", encoding="utf-8", errors="ignore") as f:
                corpus = f.read()
        except Exception:
            corpus = DEFAULT_CORPUS
    else:
        corpus = DEFAULT_CORPUS

    # With a larger corpus, lower k is better; with small, higher k is safer.
    # We'll pick k based on corpus size.
    corp_letters = len(re.sub(r"[^A-Z]", "", corpus.upper()))
    k = 0.25 if corp_letters >= 60000 else 0.5

    lp2, _ = _ngram_logprobs_dense(corpus, 2, k=k)
    lp3, _ = _ngram_logprobs_dense(corpus, 3, k=k)
    lp4, _ = _ngram_logprobs_dense(corpus, 4, k=k)

    if nL < 120:
        W4, W3, W2 = 0.75, 0.22, 0.05
    elif nL < 250:
        W4, W3, W2 = 1.05, 0.22, 0.06
    else:
        W4, W3, W2 = 1.25, 0.22, 0.06
    _scale_dense(lp4, W4)
    _scale_dense(lp3, W3)
    _scale_dense(lp2, W2)

    # Precompute positions by cipher letter for fast delta
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
        d = _freq_start_key(CT, AZ)  # cipher->plain dict
        arr = [0] * 26               # P[cipher_idx] = plain_idx
        for c_ch, p_ch in d.items():
            arr[A2I[c_ch]] = A2I[p_ch]
        return arr

    def apply_fixed_perm(P):
        """
        Apply fixed cipher->plain constraints to permutation P while keeping P a valid permutation.
        fixed is expected as dict like {"X":"E", "Q":"T"} meaning cipher X -> plain E.
        """
        if not fixed:
            return

        locked = []
        for c, p in fixed.items():
            if not c or not p:
                continue
            cU, pU = str(c).upper(), str(p).upper()
            if cU in A2I and pU in A2I:
                locked.append((A2I[cU], A2I[pU]))

        # Enforce constraints via swaps
        for c_idx, p_idx in locked:
            if P[c_idx] == p_idx:
                continue
            j = P.index(p_idx)
            P[c_idx], P[j] = P[j], P[c_idx]

    # =========================
    #   Scoring: fast n-gram
    # =========================
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

        for kind, s0 in affected:
            if kind == "q":
                x = [P[L[s0 + k]] for k in range(4)]
                old_s += lp4[((x[0] * 26 + x[1]) * 26 + x[2]) * 26 + x[3]]
                y = [
                    Pb if L[s0 + k] == a else Pa if L[s0 + k] == b else x[k]
                    for k in range(4)
                ]
                new_s += lp4[((y[0] * 26 + y[1]) * 26 + y[2]) * 26 + y[3]]
            elif kind == "t":
                x = [P[L[s0 + k]] for k in range(3)]
                old_s += lp3[(x[0] * 26 + x[1]) * 26 + x[2]]
                y = [
                    Pb if L[s0 + k] == a else Pa if L[s0 + k] == b else x[k]
                    for k in range(3)
                ]
                new_s += lp3[(y[0] * 26 + y[1]) * 26 + y[2]]
            else:
                x0, x1 = P[L[s0]], P[L[s0 + 1]]
                old_s += lp2[x0 * 26 + x1]
                y0 = Pb if L[s0] == a else Pa if L[s0] == b else x0
                y1 = Pb if L[s0 + 1] == a else Pa if L[s0 + 1] == b else x1
                new_s += lp2[y0 * 26 + y1]

        return new_s - old_s

    # =========================
    #   Semantic / dictionary-style bonus
    # =========================
    COMMON_WORDS = (
        "the and to of a in that it is was for on with as you at be this have not are but he his "
        "they we by from or an one all their there what so up out if about who get which go me when "
        "make can like no just him her said had were them then some into more time would your now "
        "only little very than people could first over after also even because new where most use "
        "work find give long day man woman life world government country system telegraph message "
        "signal liberty freedom human men women power letter matter england america union army "
        "president minister"
    ).split()

    GOOD_NGRAMS = re.compile(r"(th|he|in|er|an|re|on|at|en|nd|tion|ment|ally|ence|able)")
    BAD_DOUBLE = re.compile(r"(qq|jj|vv|ww|xx|zz)")

    EN_FREQ = {
        "E": 0.127, "T": 0.091, "A": 0.082, "O": 0.075, "I": 0.070,
        "N": 0.067, "S": 0.063, "H": 0.061, "R": 0.060, "D": 0.043,
        "L": 0.040, "C": 0.028, "U": 0.028, "M": 0.024, "W": 0.024,
        "F": 0.022, "G": 0.020, "Y": 0.020, "P": 0.019, "B": 0.015,
        "V": 0.010, "K": 0.008, "X": 0.002, "J": 0.002, "Q": 0.001, "Z": 0.001,
    }

    def semantic_bonus(text):
        t = text.lower()
        b = 0.0
        for w in COMMON_WORDS:
            b += 0.18 * len(re.findall(rf"\b{re.escape(w)}\b", t))
        b += 0.15 * len(re.findall(r"\b(a|i)\b", t))
        b += 0.04 * len(GOOD_NGRAMS.findall(t))
        b -= 0.3 * len(BAD_DOUBLE.findall(t))
        return b

    def freq_profile_bonus(text):
        t = [ch for ch in text.upper() if "A" <= ch <= "Z"]
        n = len(t)
        if n == 0:
            return 0.0
        counts = Counter(t)
        chi2 = 0.0
        for c, p in EN_FREQ.items():
            obs = counts.get(c, 0) / n
            chi2 += (obs - p) * (obs - p) / (p + 1e-9)
        return -3.8 * chi2

    def total_value_perm(P_):
        kd = {AZ[c]: AZ[P_[c]] for c in range(26)}  # cipher->plain
        pt = apply_substitution(CT, kd)
        return full_score(P_) + semantic_bonus(pt) + freq_profile_bonus(pt)

    # =========================
    #   NEW: incremental chi² pressure inside SA
    # =========================
    cipher_counts = [0] * 26
    for c in L:
        cipher_counts[c] += 1
    Nletters = sum(cipher_counts)

    EN_FREQ_ARR = [0.0] * 26
    for ch, p in EN_FREQ.items():
        EN_FREQ_ARR[A2I[ch]] = p

    def chi2_contrib(obs_count, exp_count):
        return (obs_count - exp_count) ** 2 / (exp_count + 1e-9)

    def chi2_score_from_plain_counts(plain_counts):
        chi2 = 0.0
        for i in range(26):
            exp = EN_FREQ_ARR[i] * Nletters
            chi2 += chi2_contrib(plain_counts[i], exp)
        return chi2

    def delta_swap_chi2(plain_counts, a, b, Pa, Pb):
        if Pa == Pb:
            return 0.0
        ca = cipher_counts[a]
        cb = cipher_counts[b]
        oldA = plain_counts[Pa]
        oldB = plain_counts[Pb]
        newA = oldA - ca + cb
        newB = oldB - cb + ca
        expA = EN_FREQ_ARR[Pa] * Nletters
        expB = EN_FREQ_ARR[Pb] * Nletters
        old = chi2_contrib(oldA, expA) + chi2_contrib(oldB, expB)
        new = chi2_contrib(newA, expA) + chi2_contrib(newB, expB)
        return new - old

    def one_restart(ridx, init_kind):
        rng = random.Random((seed or 0) + 1337 * ridx + hash(init_kind))

        # Initialize
        P = freq_start_key_list() if init_kind == "freq" else new_random_key(rng)

        # Slight bias for random starts: swap a few letters toward ETAOIN-ish alignment
        if init_kind == "rand":
            for _ in range(12):
                a, b = rng.randrange(26), rng.randrange(26)
                P[a], P[b] = P[b], P[a]

        apply_fixed_perm(P)

        # Init chi² tracking
        plain_counts = [0] * 26
        for c in range(26):
            plain_counts[P[c]] += cipher_counts[c]
        chi2_val = chi2_score_from_plain_counts(plain_counts)

        best_ng = full_score(P)
        best_total_seen = total_value_perm(P)
        best_total_P = P[:]

        # Annealing parameters
        T0, T_end = 7.5, 0.25
        stag, stag_limit = 0, 1600
        steps = sa_steps
        reheat_at = steps // 2

        for step in range(1, steps + 1):
            if time.time() - start_time > time_limit_seconds:
                break

            if step % 2200 == 0:
                T0 *= 0.92
            if step == reheat_at:
                T0 *= 0.92

            T = T0 * ((T_end / T0) ** (step / steps))

            a, b = rng.randrange(26), rng.randrange(26)
            if a == b:
                continue

            # Respect fixed constraints
            if fixed:
                a_ch, b_ch = AZ[a], AZ[b]
                if a_ch in fixed or b_ch in fixed:
                    continue

            Pa, Pb = P[a], P[b]

            d_ng = delta_swap(P, a, b)
            d_chi = delta_swap_chi2(plain_counts, a, b, Pa, Pb)
            d_total = d_ng - chi_weight * d_chi

            if d_total > 0 or rng.random() < math.exp(d_total / max(T, 1e-12)):
                # accept swap
                P[a], P[b] = P[b], P[a]
                best_ng += d_ng

                if Pa != Pb:
                    ca = cipher_counts[a]
                    cb = cipher_counts[b]
                    plain_counts[Pa] = plain_counts[Pa] - ca + cb
                    plain_counts[Pb] = plain_counts[Pb] - cb + ca
                    chi2_val += d_chi

                stag = 0
            else:
                stag += 1

            # occasional small greedy push when stuck
            if stag >= stag_limit:
                stag = 0
                for _ in range(16):
                    x, y = rng.randrange(26), rng.randrange(26)
                    if x == y:
                        continue
                    if fixed and (AZ[x] in fixed or AZ[y] in fixed):
                        continue
                    dd = delta_swap(P, x, y)
                    if dd > 0:
                        Px, Py = P[x], P[y]
                        dchi = delta_swap_chi2(plain_counts, x, y, Px, Py)
                        P[x], P[y] = P[y], P[x]
                        best_ng += dd
                        if Px != Py:
                            cx = cipher_counts[x]
                            cy = cipher_counts[y]
                            plain_counts[Px] = plain_counts[Px] - cx + cy
                            plain_counts[Py] = plain_counts[Py] - cy + cx
                            chi2_val += dchi

            # checkpoint on the real combined scoring model
            if checkpoint_every and (step % checkpoint_every == 0):
                v = total_value_perm(P)
                if v > best_total_seen:
                    best_total_seen = v
                    best_total_P = P[:]

        # Continue from best-by-combined-score checkpoint (important)
        P = best_total_P[:]

        # Greedy local polish on pure n-gram score (fast)
        improved = True
        while improved and time.time() - start_time < time_limit_seconds:
            improved = False
            for a in range(26):
                if fixed and AZ[a] in fixed:
                    continue
                for b in range(a + 1, 26):
                    if fixed and AZ[b] in fixed:
                        continue
                    d = delta_swap(P, a, b)
                    if d > 1e-6:
                        P[a], P[b] = P[b], P[a]
                        improved = True

        # Deterministic cleanup on combined score (candidate-limited)
        EPS = 1e-9
        improved = True
        while improved and time.time() - start_time < time_limit_seconds:
            improved = False
            base_val = total_value_perm(P)
            best_gain, best_pair = 0.0, None

            CANDIDATES = list(range(26))
            rng.shuffle(CANDIDATES)
            LIMIT = 14 if _running_on_render() else 20

            for a_i in range(LIMIT):
                a = CANDIDATES[a_i]
                if fixed and AZ[a] in fixed:
                    continue
                for b_i in range(a_i + 1, LIMIT):
                    b = CANDIDATES[b_i]
                    if fixed and AZ[b] in fixed:
                        continue

                    P[a], P[b] = P[b], P[a]
                    cand_val = total_value_perm(P)
                    P[a], P[b] = P[b], P[a]

                    gain = cand_val - base_val
                    if gain > best_gain + EPS:
                        best_gain, best_pair = gain, (a, b)

            if best_pair:
                a, b = best_pair
                P[a], P[b] = P[b], P[a]
                improved = True

        # GLOBAL FULL-PAIR DISAMBIGUATION (expensive but very helpful at the end)
        max_passes = 3 if _running_on_render() else 10
        for _ in range(max_passes):
            if time.time() - start_time > time_limit_seconds:
                break

            base_val = total_value_perm(P)
            best_gain = 0.0
            best_pair = None

            for a in range(26):
                if fixed and AZ[a] in fixed:
                    continue
                for b in range(a + 1, 26):
                    if fixed and AZ[b] in fixed:
                        continue
                    P[a], P[b] = P[b], P[a]
                    cand_val = total_value_perm(P)
                    P[a], P[b] = P[b], P[a]
                    gain = cand_val - base_val
                    if gain > best_gain + EPS:
                        best_gain = gain
                        best_pair = (a, b)

            if best_pair is None:
                break

            a, b = best_pair
            P[a], P[b] = P[b], P[a]

        # Ensure fixed constraints satisfied
        apply_fixed_perm(P)
        return P, total_value_perm(P)

    # --- Multi-restart ---
    jobs = [("freq" if i == 0 else "rand") for i in range(max_restarts)]
    results = []

    if threads_local == 1:
        for ridx, kind in enumerate(jobs):
            results.append(one_restart(ridx, kind))
            if verbose:
                sys.stdout.write(f"\r[restart {ridx + 1}/{len(jobs)} done]")
                sys.stdout.flush()
    else:
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

    key_cipher_to_plain = {AZ[c]: AZ[bestP[c]] for c in range(26)}
    plain = apply_substitution(CT, key_cipher_to_plain)

    if verbose:
        dur = time.time() - start_time
        print(f"[done in {dur:.1f}s | restarts={len(jobs)} | threads={threads_local}]")

    return key_cipher_to_plain, plain


# =========================
#   Helpers
# =========================
def _ngram_logprobs_dense(corpus, n, k=0.5):
    AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    A2I = {c: i for i, c in enumerate(AZ)}
    t = re.sub(r"[^A-Z]", "", corpus.upper())

    # If user gives a tiny corpus, pad it a bit, but don't overdo repetition.
    # (Still better to supply a larger corpus via corpus_path.)
    if len(t) < 24000:
        mul = (24000 // max(1, len(t))) + 1
        t = (t * mul)[:24000]

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
    arr = [floor] * vocab
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
    # fixed is cipher->plain, just overwrite (used only in short-text fallback)
    for c, p in fixed.items():
        if not c or not p:
            continue
        cU, pU = str(c).upper(), str(p).upper()
        if "A" <= cU <= "Z" and "A" <= pU <= "Z":
            key_dict[cU] = pU
