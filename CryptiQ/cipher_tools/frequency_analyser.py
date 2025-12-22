import math
from collections import Counter

normal_distribution = {
    "a": 0.08167, "b": 0.01492, "c": 0.02782, "d": 0.04253,
    "e": 0.12702, "f": 0.02228, "g": 0.02015, "h": 0.06094,
    "i": 0.06966, "j": 0.00153, "k": 0.00772, "l": 0.04025,
    "m": 0.02406, "n": 0.06749, "o": 0.07507, "p": 0.01929,
    "q": 0.00095, "r": 0.05987, "s": 0.06327, "t": 0.09056,
    "u": 0.02758, "v": 0.00978, "w": 0.02360, "x": 0.00150,
    "y": 0.01974, "z": 0.00074
}

def analyse(message):
    # --- Clean and prep (FIX: lowercase so stats match normal_distribution) ---
    message = ''.join(ch.lower() for ch in message if ch.isalpha())
    n = len(message)
    if n == 0:
        return [], [], [], "No alphabetic content"

    # --- Count frequencies ---
    freq = Counter(message)
    total = n

    # freq_dist: keep your structure (letter, count), sorted by count desc
    freq_dist = sorted(freq.items(), key=lambda x: x[1], reverse=True)

    # --- Build observed vector in a..z order ---
    letters = list(normal_distribution.keys())  # already a..z in your dict
    obs = [freq.get(l, 0) for l in letters]
    rel_freqs = [c / total for c in obs]

    # --- Correlation with English distribution ---
    normal_vals = [normal_distribution[l] for l in letters]
    mean1 = sum(normal_vals) / 26
    mean2 = sum(rel_freqs) / 26
    numerator = sum((a - mean1) * (b - mean2) for a, b in zip(normal_vals, rel_freqs))
    denominator = math.sqrt(
        sum((a - mean1) ** 2 for a in normal_vals) *
        sum((b - mean2) ** 2 for b in rel_freqs)
    )
    corr = numerator / denominator if denominator else 0.0

    # --- Index of Coincidence ---
    ic = sum(v * (v - 1) for v in freq.values()) / (n * (n - 1)) if n > 1 else 0.0

    # --- Chi-squared distance to English (helps reduce false poly flags) ---
    # Lower chi2 => closer to English letter distribution.
    exp = [normal_distribution[l] * total for l in letters]
    chi2 = 0.0
    for o, e in zip(obs, exp):
        if e > 0:
            chi2 += ((o - e) ** 2) / e

    # --- Identify likely cipher type (more robust thresholds) ---
    # Notes:
    # - Transposition often: high corr + relatively English-like chi2
    # - Monoalphabetic substitution often: IC near English-ish, but corr can be moderate
    # - Polyalphabetic often: IC drops notably
    if n < 20:
        cipher_type = "Uncertain — text too short for reliable stats"
    else:
        if corr > 0.80 and chi2 < 200:
            cipher_type = "Transposition (letter order changed, frequencies intact)"
        elif ic >= 0.058:
            cipher_type = "Monoalphabetic Substitution (Caesar, Affine, etc.)"
        elif ic < 0.050:
            cipher_type = "Polyalphabetic Substitution (Vigenère or similar)"
        else:
            # middle zone: could be substitution, transposition, or short-ish poly
            cipher_type = "Uncertain — possibly mixed or short text"

    # --- Common n-grams (same outputs: top 10 trigrams + bigrams) ---
    trigrams = Counter(message[i:i+3] for i in range(len(message) - 2)).most_common(10)
    bigrams  = Counter(message[i:i+2] for i in range(len(message) - 1)).most_common(10)

    return trigrams, bigrams, freq_dist, cipher_type
