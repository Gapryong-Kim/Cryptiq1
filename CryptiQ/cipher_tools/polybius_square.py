#!/usr/bin/env python3
# substitution_solver_fast.py
# Fast + accurate monoalphabetic substitution solver (Windows-safe threading)
# Tuned for LONG ciphertexts: stronger 4-grams, larger corpus, 2-phase polish.

import math, random, re, time, sys, os
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

alphabet = [
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
]



def polybius_standardize(message):
    message = message.replace(" ", "")
    coords = []
    coord = ""
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
#   Public API (2 funcs)
# =========================
def apply_substitution(text, key_cipher_to_plain):
    """Apply cipher→plain key to text, preserving non-letters and input case."""
    out = []
    for ch in text:
        if ch.isalpha():
            up = ch.upper()
            mapped = key_cipher_to_plain.get(up, up)
            out.append(mapped.lower() if ch.islower() else mapped)
        else:
            out.append(ch)
    return "".join(out)


def substitution_break(ciphertext,
                       max_restarts=14,
                       sa_steps=9000,
                       seed=None,
                       time_limit_seconds=35,
                       threads=None,
                       fixed=None,
                       verbose=True):
    """
    Fast + accurate monoalphabetic substitution solver (delta scoring + threaded restarts).
    Tuned for LONG texts (150+ letters):
      • Larger embedded corpus for n-grams
      • Heavier tetragram weight
      • SA with light reheating
      • Greedy delta polish + semantic polish (tiny word bonus)
    """
    if seed is not None:
        random.seed(seed)

    start_time = time.time()
    AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    A2I = {c: i for i, c in enumerate(AZ)}

    # --------- Normalize ciphertext to int array (letters-only) ---------
    CT = ciphertext
    CT_UP = CT.upper()
    letters_idx = [A2I[ch] for ch in CT_UP if 'A' <= ch <= 'Z']
    L = letters_idx
    nL = len(L)

    # Quick fallback for very short texts
    if nL < 8:
        key = _freq_start_key(CT, AZ)
        if fixed:
            _apply_fixed(key, fixed)
        return apply_substitution(CT, key), key

    # --------- Larger English model ---------
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

    # Weight bias for long texts (4-gram dominant)
    W4, W3, W2 = 1.20, 0.22, 0.06
    _scale_dense(lp4, W4)
    _scale_dense(lp3, W3)
    _scale_dense(lp2, W2)

    # --------- Structures for fast delta scoring ---------
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

    def full_score(P):
        s = 0.0
        if nL >= 4:
            for i in range(nL - 3):
                a, b, c, d = P[L[i]], P[L[i + 1]], P[L[i + 2]], P[L[i + 3]]
                idx = ((a * 26 + b) * 26 + c) * 26 + d
                s += lp4[idx]
        if nL >= 3:
            for i in range(nL - 2):
                a, b, c = P[L[i]], P[L[i + 1]], P[L[i + 2]]
                idx = (a * 26 + b) * 26 + c
                s += lp3[idx]
        if nL >= 2:
            for i in range(nL - 1):
                a, b = P[L[i]], P[L[i + 1]]
                idx = a * 26 + b
                s += lp2[idx]
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
                idx = ((x0 * 26 + x1) * 26 + x2) * 26 + x3
                old_s += lp4[idx]
                y0 = Pb if L[s] == a else (Pa if L[s] == b else x0)
                y1 = Pb if L[s + 1] == a else (Pa if L[s + 1] == b else x1)
                y2 = Pb if L[s + 2] == a else (Pa if L[s + 2] == b else x2)
                y3 = Pb if L[s + 3] == a else (Pa if L[s + 3] == b else x3)
                idx2 = ((y0 * 26 + y1) * 26 + y2) * 26 + y3
                new_s += lp4[idx2]
            elif kind == 't':
                x0, x1, x2 = P[L[s]], P[L[s + 1]], P[L[s + 2]]
                idx = (x0 * 26 + x1) * 26 + x2
                old_s += lp3[idx]
                y0 = Pb if L[s] == a else (Pa if L[s] == b else x0)
                y1 = Pb if L[s + 1] == a else (Pa if L[s + 1] == b else x1)
                y2 = Pb if L[s + 2] == a else (Pa if L[s + 2] == b else x2)
                idx2 = (y0 * 26 + y1) * 26 + y2
                new_s += lp3[idx2]
            else:
                x0, x1 = P[L[s]], P[L[s + 1]]
                idx = x0 * 26 + x1
                old_s += lp2[idx]
                y0 = Pb if L[s] == a else (Pa if L[s] == b else x0)
                y1 = Pb if L[s + 1] == a else (Pa if L[s + 1] == b else x1)
                idx2 = y0 * 26 + y1
                new_s += lp2[idx2]
        return new_s - old_s

    # ---- Tiny semantic word bonus (used in final polish) ----
    COMMON_WORDS = (
        "the and to of a in that it is was for on with as you at be this have not are but he his they we by from or an "
        "one all their there what so up out if about who get which go me when make can like no just him her said had were "
        "them then some into more time would your now only little very than people could first over after also even because "
        "new where most use work find give long day man woman life"
    ).split()
    WORD_BONUS = 0.3
    ONE_LETTER_BONUS = 0.12

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

    # --------- One restart (thread-friendly) ---------
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

        # Final semantic polish
        curr_score = combined_score(P)
        improved = True
        while improved and (time.time() - start_time) <= time_limit_seconds:
            improved = False
            best_gain = 0.0
            best_pair = None
            for a in range(26):
                for b in range(a + 1, 26):
                    if fixed and (_is_locked_idx(a, fixed, A2I) or _is_locked_idx(b, fixed, A2I)):
                        continue
                    d_ng = delta_swap(P, a, b)
                    if d_ng < -4.0:
                        continue
                    P[a], P[b] = P[b], P[a]
                    sc = combined_score(P)
                    P[a], P[b] = P[b], P[a]
                    gain = sc - curr_score
                    if gain > best_gain:
                        best_gain, best_pair = gain, (a, b)
            if best_pair:
                a, b = best_pair
                P[a], P[b] = P[b], P[a]
                curr_score += best_gain
                improved = True

        return P, curr_score

    # --------- Run restarts (parallel) ---------
    jobs = [('freq' if i == 0 else 'rand') for i in range(max_restarts)]
    if threads is None:
        threads = min(8, (os.cpu_count() or 2))
    threads = max(1, threads)

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

    return key_dict,plain


# =========================
#   Internal helpers
# =========================
def _ngram_logprobs_dense(corpus, n, k=0.5):
    """Build dense log-prob table for n-grams."""
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
        arr[i]
        arr[i] *= w


def _freq_start_key(text, AZ):
    """Return dict cipher→plain based on frequency order."""
    ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    t = re.sub(r"[^A-Z]", "", text.upper())
    cnt = Counter(t)
    order = [p[0] for p in cnt.most_common()]
    for a in AZ:
        if a not in order:
            order.append(a)
    return {order[i]: ENGLISH_FREQ_ORDER[i] for i in range(26)}


def _apply_fixed(key_dict, fixed):
    """Mutate key_dict to enforce cipher→plain locks."""
    for c, p in fixed.items():
        key_dict[c] = p


def _is_locked_idx(c_idx, fixed, A2I):
    return fixed is not None and (list(A2I.keys())[c_idx] in fixed)


# =========================
#   CLI for Testing
# =========================
if __name__ == "__main__":
    print("=== Monoalphabetic Substitution Solver (high accuracy, long-text tuned) ===")
    print("Paste your ciphertext, then press Enter.\n")
    cipher = input("> ").strip()
    if not cipher:
        print("No ciphertext provided.")
        sys.exit(0)

    plain, key = substitution_break(
        cipher,
        max_restarts=14,       # more restarts for long text
        sa_steps=9000,         # deeper search
        time_limit_seconds=35, # longer runtime cap
        seed=42,
        verbose=True
    )

    print("\n--- Best Guess Plaintext ---")
    print(plain)

    print("\n--- Cipher → Plain Key ---")
    AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    print(" ".join(AZ))
    print(" ".join(key.get(c, '?') for c in AZ))
    print("\n" + "  ".join(f"{c}→{key[c]}" for c in AZ))
