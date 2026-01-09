#!/usr/bin/env python3
# substitution_solver_fast.py
# Fast + accurate monoalphabetic substitution solver (Windows-safe threading)

import math, random, re, time, sys, os
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
#   Public API (2 funcs)
# =========================
def apply_substitution(text, key_cipher_to_plain):
    """Apply cipher->plain key to text, preserving non-letters and input case."""
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
                       max_restarts=12,
                       sa_steps=6000,
                       seed=None,
                       time_limit_seconds=25,
                       threads=None,
                       fixed=None,
                       verbose=True):
    """
    Fast + accurate monoalphabetic substitution solver (delta scoring + threaded restarts).

    Returns: (best_plaintext, key_cipher_to_plain_dict)

    Args:
      ciphertext: str
      max_restarts: number of independent restarts (run in parallel threads)
      sa_steps: simulated annealing steps per restart (delta scored)
      time_limit_seconds: soft cap for total wall time
      threads: None => sensible default (min(8, os.cpu_count() or 2)), 1 => single-thread
      fixed: optional dict {'C': 'P', ...} to lock some cipher->plain mappings
      verbose: print light progress
    """
    if seed is not None:
        random.seed(seed)

    start_time = time.time()
    AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    A2I = {c:i for i,c in enumerate(AZ)}
    I2A = AZ.__getitem__

    # --------- Normalize ciphertext to int array (letters-only for scoring) ---------
    CT = ciphertext
    CT_UP = CT.upper()
    letters_idx = []
    pos_map = []  # map letters-only index -> index in original text
    for i, ch in enumerate(CT_UP):
        if 'A' <= ch <= 'Z':
            letters_idx.append(A2I[ch])
            pos_map.append(i)
    L = letters_idx
    nL = len(L)

    # Quick fallback for super short texts
    if nL < 8:
        key = _freq_start_key(CT, AZ)
        if fixed: _apply_fixed(key, fixed)
        return apply_substitution(CT, key), key

    # --------- Language model (bi/tri/quad) as dense arrays (base-26 indexing) ---------
    CORPUS = """
    IT IS A TRUTH UNIVERSALLY ACKNOWLEDGED THAT A SINGLE MAN IN POSSESSION OF A GOOD FORTUNE
    MUST BE IN WANT OF A WIFE. HOWEVER LITTLE KNOWN THE FEELINGS OR VIEWS OF SUCH A MAN MAY BE
    ON HIS FIRST ENTERING A NEIGHBOURHOOD THIS TRUTH IS SO WELL FIXED IN THE MINDS OF THE
    SURROUNDING FAMILIES THAT HE IS CONSIDERED THE RIGHTFUL PROPERTY OF SOME ONE OR OTHER OF THEIR DAUGHTERS.
    THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG. WHEN YOU HAVE ELIMINATED THE IMPOSSIBLE,
    WHATEVER REMAINS, HOWEVER IMPROBABLE, MUST BE THE TRUTH.
    IN THE BEGINNING GOD CREATED THE HEAVEN AND THE EARTH. AND THE EARTH WAS WITHOUT FORM, AND VOID;
    AND DARKNESS WAS UPON THE FACE OF THE DEEP. AND THE SPIRIT OF GOD MOVED UPON THE FACE OF THE WATERS.
    AND GOD SAID LET THERE BE LIGHT AND THERE WAS LIGHT.
    """

    lp2, floor2 = _ngram_logprobs_dense(CORPUS, 2, k=0.5)
    lp3, floor3 = _ngram_logprobs_dense(CORPUS, 3, k=0.5)
    lp4, floor4 = _ngram_logprobs_dense(CORPUS, 4, k=0.5)

    # Weights: bake tri/bi weights directly into the arrays so delta is simple.
    W4, W3, W2 = 1.00, 0.25, 0.10
    _scale_dense(lp3, W3)
    _scale_dense(lp2, W2)
    # lp4 stays as-is (W4 = 1)

    # --------- Structures for fast delta rescoring ---------
    # Positions of each cipher letter (so swaps only touch nearby windows)
    pos_by_c = [[] for _ in range(26)]
    for i, c in enumerate(L):
        pos_by_c[c].append(i)

    # Precompute which n-gram windows are affected by a change at position j
    def affected_starts_for_pos(j):
        starts = set()
        if nL >= 4:
            for s in (j-3, j-2, j-1, j):
                if 0 <= s <= nL-4: starts.add(('q', s))
        if nL >= 3:
            for s in (j-2, j-1, j):
                if 0 <= s <= nL-3: starts.add(('t', s))
        if nL >= 2:
            for s in (j-1, j):
                if 0 <= s <= nL-2: starts.add(('b', s))
        return starts

    pre_affects = [affected_starts_for_pos(j) for j in range(nL)]

    # current key as list of ints P[c] = plain_index
    def new_random_key(rng):
        p = list(range(26))
        rng.shuffle(p)
        return p

    def freq_start_key_list():
        d = _freq_start_key(CT, AZ)
        arr = [0]*26
        inv = {A2I[c]: A2I[p] for c,p in d.items()}
        for c_idx in range(26):
            arr[c_idx] = inv.get(c_idx, c_idx)
        return arr

    def apply_fixed_list(P):
        if not fixed:
            return
        locked = {A2I[c]: A2I[p] for c,p in fixed.items()}
        # Place locked pairs
        for c_idx, p_idx in locked.items():
            P[c_idx] = p_idx
        # Repair permutation if any duplicates
        taken = set(locked.values())
        free_plain = [i for i in range(26) if i not in taken]
        seen = set()
        for c_idx in range(26):
            if c_idx in locked:
                seen.add(P[c_idx]); continue
            if P[c_idx] in seen or P[c_idx] in taken:
                P[c_idx] = free_plain.pop(0)
            seen.add(P[c_idx])

    def full_score(P):
        s = 0.0
        if nL >= 4:
            for i in range(nL-3):
                a,b,c,d = P[L[i]], P[L[i+1]], P[L[i+2]], P[L[i+3]]
                idx = ((a*26 + b)*26 + c)*26 + d
                s += lp4[idx]
        if nL >= 3:
            for i in range(nL-2):
                a,b,c = P[L[i]], P[L[i+1]], P[L[i+2]]
                idx = (a*26 + b)*26 + c
                s += lp3[idx]
        if nL >= 2:
            for i in range(nL-1):
                a,b = P[L[i]], P[L[i+1]]
                idx = a*26 + b
                s += lp2[idx]
        return s

    def delta_swap(P, a, b):
        """Score delta if we swap plaintext images of cipher letters a,b (ints 0..25).
           Tri/bi tables are pre-scaled; lp4 is unscaled (weight=1)."""
        affected = set()
        for j in pos_by_c[a]:
            affected |= pre_affects[j]
        for j in pos_by_c[b]:
            affected |= pre_affects[j]

        old_s = 0.0
        new_s = 0.0
        Pa, Pb = P[a], P[b]

        for kind, s in affected:
            if kind == 'q':
                x0, x1, x2, x3 = P[L[s]], P[L[s+1]], P[L[s+2]], P[L[s+3]]
                idx = ((x0*26 + x1)*26 + x2)*26 + x3
                old_s += lp4[idx]
                y0 = Pb if L[s]==a else (Pa if L[s]==b else x0)
                y1 = Pb if L[s+1]==a else (Pa if L[s+1]==b else x1)
                y2 = Pb if L[s+2]==a else (Pa if L[s+2]==b else x2)
                y3 = Pb if L[s+3]==a else (Pa if L[s+3]==b else x3)
                idx2 = ((y0*26 + y1)*26 + y2)*26 + y3
                new_s += lp4[idx2]
            elif kind == 't':
                x0, x1, x2 = P[L[s]], P[L[s+1]], P[L[s+2]]
                idx = (x0*26 + x1)*26 + x2
                old_s += lp3[idx]
                y0 = Pb if L[s]==a else (Pa if L[s]==b else x0)
                y1 = Pb if L[s+1]==a else (Pa if L[s+1]==b else x1)
                y2 = Pb if L[s+2]==a else (Pa if L[s+2]==b else x2)
                idx2 = (y0*26 + y1)*26 + y2
                new_s += lp3[idx2]
            else:
                x0, x1 = P[L[s]], P[L[s+1]]
                idx = x0*26 + x1
                old_s += lp2[idx]
                y0 = Pb if L[s]==a else (Pa if L[s]==b else x0)
                y1 = Pb if L[s+1]==a else (Pa if L[s+1]==b else x1)
                idx2 = y0*26 + y1
                new_s += lp2[idx2]
        return new_s - old_s

    # --------- One restart (thread-friendly) ---------
    def one_restart(ridx, init_kind):
        rng = random.Random((seed or 0) + 1337*ridx + hash(init_kind))
        P = freq_start_key_list() if init_kind == 'freq' else new_random_key(rng)
        apply_fixed_list(P)

        best = full_score(P)
        T0, T_end = 6.5, 0.35
        stagnation, stag_limit = 0, 1200
        steps = sa_steps

        # Simulated annealing with delta scoring
        for step in range(1, steps+1):
            if time.time() - start_time > time_limit_seconds:
                break
            T = T0 * ((T_end / T0) ** (step / steps))
            a, b = rng.randrange(26), rng.randrange(26)
            if a == b:
                continue
            if fixed and ((_is_locked_idx(a, fixed, A2I)) or (_is_locked_idx(b, fixed, A2I))):
                continue
            d = delta_swap(P, a, b)
            if d >= 0 or rng.random() < math.exp(d / max(T, 1e-12)):
                P[a], P[b] = P[b], P[a]
                best += d
                stagnation = 0
            else:
                stagnation += 1

            if stagnation >= stag_limit:
                stagnation = 0
                # Shake: accept a few beneficial random swaps if found
                for _ in range(12):
                    x, y = rng.randrange(26), rng.randrange(26)
                    if fixed and (_is_locked_idx(x, fixed, A2I) or _is_locked_idx(y, fixed, A2I)):
                        continue
                    dd = delta_swap(P, x, y)
                    if dd > 0:
                        P[x], P[y] = P[y], P[x]
                        best += dd

        # Greedy steepest-ascent polish
        improved = True
        while improved and (time.time() - start_time) <= time_limit_seconds:
            improved = False
            best_impr = 0.0
            best_pair = None
            for a in range(26):
                for b in range(a+1, 26):
                    if fixed and (_is_locked_idx(a, fixed, A2I) or _is_locked_idx(b, fixed, A2I)):
                        continue
                    d = delta_swap(P, a, b)
                    if d > best_impr + 1e-9:
                        best_impr = d
                        best_pair = (a, b)
            if best_pair:
                a,b = best_pair
                P[a], P[b] = P[b], P[a]
                best += best_impr
                improved = True

        return P, best

    # --------- Plan restarts (mix frequency + random) ---------
    jobs = [('freq' if i==0 else 'rand') for i in range(max_restarts)]

    # Thread count
    if threads is None:
        threads = min(8, (os.cpu_count() or 2))
    threads = max(1, threads)

    # Run threaded restarts
    results = []
    if threads == 1:
        for ridx, kind in enumerate(jobs):
            results.append(one_restart(ridx, kind))
            if verbose:
                sys.stdout.write(f"\r[restart {ridx+1}/{len(jobs)} done]"); sys.stdout.flush()
    else:
        with ThreadPoolExecutor(max_workers=threads) as exe:
            fut_to_id = {exe.submit(one_restart, ridx, kind): (ridx, kind) for ridx, kind in enumerate(jobs)}
            for n, fut in enumerate(as_completed(fut_to_id), 1):
                results.append(fut.result())
                if verbose:
                    sys.stdout.write(f"\r[completed {n}/{len(jobs)} restarts]"); sys.stdout.flush()

    if verbose:
        print("")

    # Pick best key
    bestP, bestScore = max(results, key=lambda z: z[1])

    # Render plaintext
    key_dict = {AZ[c]: AZ[bestP[c]] for c in range(26)}
    plain = apply_substitution(CT, key_dict)

    if verbose:
        dur = time.time() - start_time
        print(f"[done in {dur:.1f}s | restarts={len(jobs)} | threads={threads}]")

    return plain, key_dict


# =========================
#   Internal helpers
# =========================
def _ngram_logprobs_dense(corpus, n, k=0.5):
    """
    Build dense log-prob table for n-grams as a list of length 26^n.
    Base-26 index: for gram g0..g{n-1}, idx = (((g0)*26+g1)*26+g2)...
    """
    AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    A2I = {c:i for i,c in enumerate(AZ)}
    t = re.sub(r"[^A-Z]", "", corpus.upper())
    if len(t) < 2000:
        t = (t * (2000 // max(1, len(t)) + 1))[:2000]
    counts = Counter()
    for i in range(len(t)-n+1):
        idx = 0
        for j in range(n):
            idx = idx*26 + A2I[t[i+j]]
        counts[idx] += 1
    total = sum(counts.values())
    vocab = 26 ** n
    denom = total + k * vocab
    # Fill dense array with floor
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
    """Return dict cipher->plain based on frequency order."""
    ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    t = re.sub(r"[^A-Z]", "", text.upper())
    cnt = Counter(t)
    order = [p[0] for p in cnt.most_common()]
    for a in AZ:
        if a not in order:
            order.append(a)
    return {order[i]: ENGLISH_FREQ_ORDER[i] for i in range(26)}

def _apply_fixed(key_dict, fixed):
    """Mutate key_dict to enforce cipher->plain locks."""
    for c, p in fixed.items():
        key_dict[c] = p

def _is_locked_idx(c_idx, fixed, A2I):
    return fixed is not None and (list(A2I.keys())[c_idx] in fixed)


# =========================
#   CLI (for quick testing)
# =========================

 
