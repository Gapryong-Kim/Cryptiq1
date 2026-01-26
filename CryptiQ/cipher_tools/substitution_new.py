#!/usr/bin/env python3
# substitution_solver_fast.py
# Fast + more accurate monoalphabetic substitution solver (Windows-safe threading)

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
                       max_restarts=18,
                       sa_steps=9000,
                       seed=None,
                       time_limit_seconds=25,
                       threads=None,
                       fixed=None,
                       verbose=True):
    """
    Improved monoalphabetic substitution solver:
      - stronger embedded LM (bigger corpus)
      - proposes swaps mostly on letters that appear
      - correct fixed-lock handling
      - fast delta scoring + threaded restarts
      - adds small word-structure bonus for better convergence

    Returns: (best_plaintext, key_cipher_to_plain_dict)
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
    for ch in CT_UP:
        if 'A' <= ch <= 'Z':
            letters_idx.append(A2I[ch])
    L = letters_idx
    nL = len(L)

    # Quick fallback for super short texts
    if nL < 12:
        key = _freq_start_key(CT, AZ)
        if fixed:
            _apply_fixed(key, fixed)
        return apply_substitution(CT, key), key

    # =========================
    # Stronger embedded corpus
    # =========================
    # (Still lightweight, but much broader than a couple paragraphs.)
    CORPUS = """
    THE PROJECT GUTENBERG EBOOK OF THE ADVENTURES OF SHERLOCK HOLMES BY ARTHUR CONAN DOYLE
    TO SHERLOCK HOLMES SHE IS ALWAYS THE WOMAN. I HAVE SELDOM HEARD HIM MENTION HER UNDER ANY OTHER NAME.
    IN HIS EYES SHE ECLIPSES AND PREDOMINATES THE WHOLE OF HER SEX.

    IT WAS THE BEST OF TIMES IT WAS THE WORST OF TIMES IT WAS THE AGE OF WISDOM IT WAS THE AGE OF FOOLISHNESS
    IT WAS THE EPOCH OF BELIEF IT WAS THE EPOCH OF INCREDULITY IT WAS THE SEASON OF LIGHT IT WAS THE SEASON OF DARKNESS

    IN THE BEGINNING GOD CREATED THE HEAVEN AND THE EARTH. AND THE EARTH WAS WITHOUT FORM AND VOID
    AND DARKNESS WAS UPON THE FACE OF THE DEEP. AND THE SPIRIT OF GOD MOVED UPON THE FACE OF THE WATERS.

    WHEN YOU HAVE ELIMINATED THE IMPOSSIBLE WHATEVER REMAINS HOWEVER IMPROBABLE MUST BE THE TRUTH.
    THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG.

    WE HOLD THESE TRUTHS TO BE SELF EVIDENT THAT ALL MEN ARE CREATED EQUAL THAT THEY ARE ENDOWED BY THEIR CREATOR
    WITH CERTAIN UNALIENABLE RIGHTS THAT AMONG THESE ARE LIFE LIBERTY AND THE PURSUIT OF HAPPINESS.

    CALL ME ISHMAEL. SOME YEARS AGO NEVER MIND HOW LONG PRECISELY HAVING LITTLE OR NO MONEY IN MY PURSE
    AND NOTHING PARTICULAR TO INTEREST ME ON SHORE I THOUGHT I WOULD SAIL ABOUT A LITTLE AND SEE THE WATERY PART OF THE WORLD.

    ALICE WAS BEGINNING TO GET VERY TIRED OF SITTING BY HER SISTER ON THE BANK AND OF HAVING NOTHING TO DO.
    ONCE OR TWICE SHE HAD PEEPED INTO THE BOOK HER SISTER WAS READING BUT IT HAD NO PICTURES OR CONVERSATIONS IN IT.

    IT IS A TRUTH UNIVERSALLY ACKNOWLEDGED THAT A SINGLE MAN IN POSSESSION OF A GOOD FORTUNE MUST BE IN WANT OF A WIFE.
    """

    lp2, _ = _ngram_logprobs_dense(CORPUS, 2, k=0.35)
    lp3, _ = _ngram_logprobs_dense(CORPUS, 3, k=0.35)
    lp4, _ = _ngram_logprobs_dense(CORPUS, 4, k=0.35)

    # Weights
    W4, W3, W2 = 1.00, 0.30, 0.12
    _scale_dense(lp3, W3)
    _scale_dense(lp2, W2)

    # =========================
    # Word-structure bonus
    # =========================
    # Very cheap “English-ness” signal. Helps a LOT on real subs.
    COMMON_WORDS = {
        "THE","AND","THAT","HAVE","FOR","NOT","WITH","YOU","THIS","BUT","HIS","FROM","THEY","SAY","HER","SHE",
        "WILL","ONE","ALL","WOULD","THERE","THEIR","WHAT","SO","UP","OUT","IF","ABOUT","WHO","GET","WHICH","GO",
        "ME","WHEN","MAKE","CAN","LIKE","TIME","JUST","HIM","KNOW","TAKE","PEOPLE","INTO","YEAR","YOUR","GOOD",
        "SOME","COULD","THEM","SEE","OTHER","THAN","THEN","NOW","LOOK","ONLY","COME","ITS","OVER","THINK","ALSO",
        "BACK","AFTER","USE","TWO","HOW","OUR","WORK","FIRST","WELL","WAY","EVEN","NEW","WANT","BECAUSE","ANY",
        "THESE","GIVE","DAY","MOST","US","IS","ARE","WAS","WERE","I","A","TO","OF","IN","IT","ON","AS","AT","BE"
    }
    # a few super-informative short patterns (no spaces needed)
    COMMON_TRIGRAMS = ("THE","AND","ING","HER","HAT","HIS","ERE","ENT","ION","TIO","FOR","THA","NTH","WAS","YOU","VER")

    def wordish_bonus(decoded_upper):
        """
        decoded_upper: letters+punct possibly, already uppercase.
        Gives a small bonus for common short words + common trigrams.
        """
        # Split on non-letters
        words = re.findall(r"[A-Z]{2,}", decoded_upper)
        if not words:
            return 0.0

        bonus = 0.0
        # Reward common words (caps)
        for w in words:
            if w in COMMON_WORDS:
                # stronger for 2-4 letter words (they anchor substitution)
                if len(w) <= 4:
                    bonus += 2.2
                else:
                    bonus += 1.0

        # Reward common trigrams in the raw stream
        s = re.sub(r"[^A-Z]", "", decoded_upper)
        for tri in COMMON_TRIGRAMS:
            bonus += 0.18 * s.count(tri)

        # Small penalty if it’s “vowelless soup”
        # (too few vowels often indicates bad mapping)
        if s:
            vowels = sum(ch in "AEIOU" for ch in s)
            frac = vowels / len(s)
            if frac < 0.25:
                bonus -= 3.0
            elif frac > 0.50:
                bonus -= 1.5

        return bonus

    # --------- Structures for fast delta rescoring ---------
    # Positions of each cipher letter
    pos_by_c = [[] for _ in range(26)]
    for i, c in enumerate(L):
        pos_by_c[c].append(i)

    # Only consider swapping letters that appear (huge win)
    present_cipher = [c for c in range(26) if pos_by_c[c]]
    if len(present_cipher) < 6:
        present_cipher = list(range(26))

    # Precompute windows affected by a change at position j
    def affected_starts_for_pos(j):
        starts = []
        if nL >= 4:
            for s in (j-3, j-2, j-1, j):
                if 0 <= s <= nL-4:
                    starts.append(('q', s))
        if nL >= 3:
            for s in (j-2, j-1, j):
                if 0 <= s <= nL-3:
                    starts.append(('t', s))
        if nL >= 2:
            for s in (j-1, j):
                if 0 <= s <= nL-2:
                    starts.append(('b', s))
        return starts

    pre_affects = [affected_starts_for_pos(j) for j in range(nL)]

    # Precompute affected window starts per cipher letter (avoid set union churn)
    aff_by_c = [None]*26
    for c in range(26):
        seen = set()
        lst = []
        for j in pos_by_c[c]:
            for item in pre_affects[j]:
                if item not in seen:
                    seen.add(item)
                    lst.append(item)
        aff_by_c[c] = lst

    # current key as list of ints P[c] = plain_index
    def new_random_key(rng):
        p = list(range(26))
        rng.shuffle(p)
        return p

    def freq_start_key_list():
        d = _freq_start_key(CT, AZ)
        # d maps cipher_letter -> plain_letter
        arr = [0]*26
        for c in range(26):
            cl = AZ[c]
            pl = d.get(cl, cl)
            arr[c] = A2I[pl]
        return arr

    def apply_fixed_list(P):
        if not fixed:
            return
        locked = {A2I[c.upper()]: A2I[p.upper()] for c,p in fixed.items()}

        # write locked
        for c_idx, p_idx in locked.items():
            P[c_idx] = p_idx

        # repair into a permutation
        used = set()
        for c in range(26):
            if c in locked:
                used.add(P[c])

        free_plain = [i for i in range(26) if i not in used]

        # If duplicates exist in unlocked area, replace with free_plain
        seen_plain = set(locked.values())
        for c in range(26):
            if c in locked:
                continue
            if P[c] in seen_plain:
                P[c] = free_plain.pop(0)
            seen_plain.add(P[c])

    def is_locked_idx(c_idx):
        return fixed is not None and (AZ[c_idx] in {k.upper() for k in fixed.keys()})

    # Fast render of only letters into uppercase decoded stream for word bonus
    def decode_letters_only_upper(P):
        # map cipher idx -> plain idx
        return "".join(I2A(P[c]) for c in L)

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

        # Add light wordish signal
        # (We only use letters stream, but it still helps a lot.)
        s += 0.65 * wordish_bonus(decode_letters_only_upper(P))
        return s

    def delta_swap(P, a, b):
        """Score delta if we swap plaintext images of cipher letters a,b."""
        affected = aff_by_c[a]
        if a != b:
            # merge affected lists without sets in the common case
            # (small list sizes; this is cheap)
            seen = set(affected)
            merged = list(affected)
            for item in aff_by_c[b]:
                if item not in seen:
                    seen.add(item)
                    merged.append(item)
            affected = merged

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

        # Approx word-bonus delta cheaply by sampling (avoid full recompute every move)
        # We do it only occasionally in the SA loop, not here.
        return new_s - old_s

    # --------- One restart (thread-friendly) ---------
    def one_restart(ridx, init_kind):
        rng = random.Random(((seed or 0) * 1000003) ^ (1337*ridx + (0 if init_kind=='freq' else 99991)))
        P = freq_start_key_list() if init_kind == 'freq' else new_random_key(rng)
        apply_fixed_list(P)

        best = full_score(P)

        # Anneal schedule
        T0, T_end = 7.2, 0.28
        steps = sa_steps

        stagnation = 0
        stag_limit = 1400

        # Simulated annealing with delta scoring
        for step in range(1, steps+1):
            if time.time() - start_time > time_limit_seconds:
                break

            T = T0 * ((T_end / T0) ** (step / steps))

            # pick from letters that appear
            a = present_cipher[rng.randrange(len(present_cipher))]
            b = present_cipher[rng.randrange(len(present_cipher))]
            if a == b:
                continue
            if fixed and (is_locked_idx(a) or is_locked_idx(b)):
                continue

            d = delta_swap(P, a, b)

            # Occasionally incorporate wordish bonus by full score refresh
            # (keeps it honest without making every step expensive)
            if (step & 511) == 0:
                cur = full_score(P)
                best = cur

            if d >= 0 or rng.random() < math.exp(d / max(T, 1e-12)):
                P[a], P[b] = P[b], P[a]
                best += d
                stagnation = 0
            else:
                stagnation += 1

            if stagnation >= stag_limit:
                stagnation = 0
                # Shake: do a few random swaps; keep if improves full score
                for _ in range(10):
                    x = present_cipher[rng.randrange(len(present_cipher))]
                    y = present_cipher[rng.randrange(len(present_cipher))]
                    if x == y:
                        continue
                    if fixed and (is_locked_idx(x) or is_locked_idx(y)):
                        continue
                    P[x], P[y] = P[y], P[x]
                    sc = full_score(P)
                    if sc >= best:
                        best = sc
                    else:
                        P[x], P[y] = P[y], P[x]

        # Greedy polish: try best improving swaps among present letters
        improved = True
        while improved and (time.time() - start_time) <= time_limit_seconds:
            improved = False
            best_impr = 0.0
            best_pair = None

            # evaluate pairs on present letters only
            for i in range(len(present_cipher)):
                a = present_cipher[i]
                if fixed and is_locked_idx(a):
                    continue
                for j in range(i+1, len(present_cipher)):
                    b = present_cipher[j]
                    if fixed and is_locked_idx(b):
                        continue
                    d = delta_swap(P, a, b)
                    if d > best_impr + 1e-9:
                        best_impr = d
                        best_pair = (a, b)

            if best_pair:
                a,b = best_pair
                P[a], P[b] = P[b], P[a]
                best += best_impr
                # re-sync with full score (includes word bonus)
                best = full_score(P)
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

    # Ensure enough length for stable counts
    if len(t) < 12000:
        reps = (12000 // max(1, len(t))) + 1
        t = (t * reps)[:12000]

    counts = Counter()
    for i in range(len(t)-n+1):
        idx = 0
        for j in range(n):
            idx = idx*26 + A2I[t[i+j]]
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
        key_dict[c.upper()] = p.upper()


# =========================
#   CLI (for quick testing)
# =========================
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("ciphertext", nargs="?", default="", help="Ciphertext string, or omit to read stdin")
    ap.add_argument("--restarts", type=int, default=18)
    ap.add_argument("--steps", type=int, default=9000)
    ap.add_argument("--time", type=float, default=25)
    ap.add_argument("--threads", type=int, default=None)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    ct = args.ciphertext
    if not ct.strip():
        ct = sys.stdin.read()

    plain, key = substitution_break(
        ct,
        max_restarts=args.restarts,
        sa_steps=args.steps,
        seed=args.seed,
        time_limit_seconds=args.time,
        threads=args.threads,
        fixed=None,
        verbose=(not args.quiet)
    )
    print("\n=== KEY (cipher->plain) ===")
    print(" ".join([f"{k}->{v}" for k,v in sorted(key.items())]))
    print("\n=== PLAINTEXT ===")
    print(plain)
