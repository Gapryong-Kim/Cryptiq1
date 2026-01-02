import math
import re
from collections import Counter, defaultdict
from flask import jsonify, request, url_for

# English letter frequencies (A–Z) as proportions
_EN_FREQ = {
    "A": 0.08167, "B": 0.01492, "C": 0.02782, "D": 0.04253, "E": 0.12702,
    "F": 0.02228, "G": 0.02015, "H": 0.06094, "I": 0.06966, "J": 0.00153,
    "K": 0.00772, "L": 0.04025, "M": 0.02406, "N": 0.06749, "O": 0.07507,
    "P": 0.01929, "Q": 0.00095, "R": 0.05987, "S": 0.06327, "T": 0.09056,
    "U": 0.02758, "V": 0.00978, "W": 0.02360, "X": 0.00150, "Y": 0.01974, "Z": 0.00074
}
_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_VOWELS = set("AEIOUY")

def _safe_top(counter: Counter, n: int):
    return [(k, int(v)) for k, v in counter.most_common(n)]

def _ioc_from_counts(counts: Counter, n: int) -> float:
    if n <= 1:
        return 0.0
    num = sum(c * (c - 1) for c in counts.values())
    den = n * (n - 1)
    return num / den

def _shannon_entropy_from_counts(counts: Counter, n: int) -> float:
    if n <= 0:
        return 0.0
    ent = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            ent -= p * math.log2(p)
    return ent

def _chisq_english(letter_counts: Counter, n: int) -> float:
    if n <= 0:
        return 0.0
    chi = 0.0
    for ch in _ALPHA:
        obs = letter_counts.get(ch, 0)
        exp = _EN_FREQ[ch] * n
        if exp > 0:
            chi += ((obs - exp) ** 2) / exp
    return chi

def _autocorr_shifts(alpha_only: str, max_shift: int = 20):
    """
    Returns matches and match-rate for shifts 1..max_shift.
    Useful for Vigenere-ish key length hints (peaks).
    """
    n = len(alpha_only)
    out = []
    if n < 2:
        return out
    for s in range(1, max_shift + 1):
        m = 0
        # compare x[i] to x[i+s]
        for i in range(n - s):
            if alpha_only[i] == alpha_only[i + s]:
                m += 1
        rate = (m / (n - s)) if (n - s) > 0 else 0.0
        out.append({"shift": s, "matches": m, "rate": round(rate, 6)})
    out.sort(key=lambda r: (r["rate"], r["matches"]), reverse=True)
    return out

def _kasiski(alpha_only: str, min_len: int = 3, max_len: int = 5, top_repeat: int = 8):
    """
    Very lightweight Kasiski: repeated ngrams -> distances -> factor counts.
    """
    n = len(alpha_only)
    if n < 20:
        return {
            "repeats": [],
            "distance_gcds": [],
            "factor_counts": []
        }

    repeats = []
    distance_counts = Counter()
    factor_counts = Counter()

    for L in range(min_len, max_len + 1):
        positions = defaultdict(list)
        for i in range(0, n - L + 1):
            ng = alpha_only[i:i+L]
            positions[ng].append(i)

        for ng, pos_list in positions.items():
            if len(pos_list) >= 2:
                # collect distances between consecutive repeats
                dists = []
                for j in range(1, len(pos_list)):
                    d = pos_list[j] - pos_list[j-1]
                    if d > 0:
                        dists.append(d)
                        distance_counts[d] += 1

                        # factors up to 20 (key length candidates)
                        for f in range(2, 21):
                            if d % f == 0:
                                factor_counts[f] += 1

                if dists:
                    repeats.append({
                        "ngram": ng,
                        "len": L,
                        "count": len(pos_list),
                        "distances": dists[:10]
                    })

    repeats.sort(key=lambda r: (r["count"], r["len"]), reverse=True)
    top_repeats = repeats[:top_repeat]

    # crude gcd suggestion: take gcd of the most common distances
    common_dists = [d for d, _c in distance_counts.most_common(10)]
    gcds = []
    for i in range(len(common_dists)):
        for j in range(i+1, len(common_dists)):
            g = math.gcd(common_dists[i], common_dists[j])
            if g >= 2 and g <= 20:
                gcds.append(g)
    gcd_counts = Counter(gcds).most_common(8)

    return {
        "repeats": top_repeats,
        "distance_gcds": [{"gcd": int(g), "count": int(c)} for g, c in gcd_counts],
        "factor_counts": [{"factor": int(f), "count": int(c)} for f, c in factor_counts.most_common(10)],
    }

def _friedman_keylen_estimate(ioc: float, n: int):
    """
    Classic Friedman estimate. Returns None if unstable.
    Uses common constants for English plaintext.
    """
    if n < 40:
        return None
    # Denominator can go near 0 or negative on weird inputs
    denom = ((n - 1) * ioc) - (0.038 * n) + 0.065
    if abs(denom) < 1e-9:
        return None
    k = (0.027 * n) / denom
    if k <= 0 or k > 40:
        return None
    return round(float(k), 2)

def _detect_encodings(raw: str):
    s = raw.strip()
    s_nospace = re.sub(r"\s+", "", s)

    # binary-ish: only 0/1 with spaces/newlines ok
    is_bin = bool(s) and bool(re.fullmatch(r"[01\s]+", s)) and (len(re.sub(r"\s+", "", s)) >= 16)

    # hex-ish: hex chars only (spaces ok)
    is_hex = bool(s) and bool(re.fullmatch(r"[0-9a-fA-F\s]+", s)) and (len(re.sub(r"\s+", "", s)) >= 16)

    # base64-ish: base64 alphabet plus = padding, length multiple of 4 is a good hint
    b64_ok = bool(re.fullmatch(r"[A-Za-z0-9+/=\s]+", s))
    b64_len = len(s_nospace)
    is_b64 = b64_ok and b64_len >= 16 and (b64_len % 4 == 0)

    return {
        "looks_binary": bool(is_bin),
        "looks_hex": bool(is_hex),
        "looks_base64": bool(is_b64),
        "base64_len_mod4": (b64_len % 4) if b64_len else None
    }

def _rank_cipher_types(features: dict):
    """
    Returns a ranked list of (label, score, reasons[]).
    This is heuristic — but it reads 'premium' and is useful.
    """
    ranks = []

    enc = features["encoding_hints"]
    ioc = features["ioc"]
    chi = features["chi_square_english"]
    ent = features["entropy_bits_per_char"]
    n_alpha = features["alpha_len"]
    autocorr = features["autocorr_top"]
    friedman = features["friedman_keylen"]

    def add(name, score, reasons):
        ranks.append({"name": name, "score": int(score), "reasons": reasons})

    # Encoding guesses (strong)
    if enc["looks_base64"]:
        add("Base64", 92, ["Valid Base64 charset", "Length multiple of 4", "High non-letter density expected"])
    if enc["looks_hex"]:
        add("Hex", 90, ["Hex charset only", "Often used to wrap bytes"])
    if enc["looks_binary"]:
        add("Binary", 88, ["Only 0/1 + whitespace"])

    # If mostly letters, do classical heuristics
    if n_alpha >= 30:
        # monoalphabetic-ish: IoC closer to English + chi-square reasonably low
        if ioc >= 0.055:
            score = 70
            reasons = [f"IoC is relatively high ({ioc:.4f}) → monoalphabetic-ish"]
            if chi > 0:
                if chi < 180:
                    score += 18
                    reasons.append(f"Chi-square vs English is low ({chi:.1f}) → distribution matches English-ish")
                else:
                    reasons.append(f"Chi-square vs English is high ({chi:.1f}) → may be substitution/transposition or short sample")
            add("Caesar / Affine / Simple Substitution", score, reasons)

        # polyalphabetic-ish: lower IoC, keylen hints
        if 0.035 <= ioc <= 0.055:
            score = 68
            reasons = [f"IoC is mid/low ({ioc:.4f}) → polyalphabetic or transposition possible"]
            if friedman:
                score += 12
                reasons.append(f"Friedman key length ≈ {friedman}")
            if autocorr:
                top = autocorr[0]
                if top["rate"] >= 0.055:
                    score += 10
                    reasons.append(f"Autocorrelation peak at shift {top['shift']} (rate {top['rate']})")
            add("Vigenère / Polyalphabetic", score, reasons)

        # transposition-ish: IoC can remain high-ish but chi-square can be worse; entropy near English-ish
        if ioc >= 0.05 and chi >= 180:
            add("Transposition (Columnar / Railfence)", 62, [
                f"IoC high-ish ({ioc:.4f}) but chi-square high ({chi:.1f})",
                "Transposition preserves single-letter counts but disrupts digrams"
            ])

        # random-ish / high entropy
        if ent >= 4.4:
            add("Compressed / Random / Modern cipher", 55, [
                f"Entropy is high ({ent:.2f} bits/char)",
                "Classical ciphers usually look less random"
            ])

    # sort and keep top
    ranks.sort(key=lambda r: r["score"], reverse=True)

    # de-dupe by name (encoding guesses might overlap)
    seen = set()
    out = []
    for r in ranks:
        if r["name"] in seen:
            continue
        seen.add(r["name"])
        out.append(r)
    return out[:6]