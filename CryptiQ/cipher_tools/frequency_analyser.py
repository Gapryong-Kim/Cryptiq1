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
    # --- Clean and prep ---
    message = ''.join(ch for ch in message.lower() if ch.isalpha())
    n = len(message)
    if n == 0:
        return [], [], [], "No alphabetic content"

    # --- Count frequencies ---
    freq = Counter(message)
    freq_dist = [(ltr, freq[ltr]) for ltr in sorted(freq)]
    total = sum(freq.values())
    rel_freqs = [freq[ltr]/total for ltr in sorted(normal_distribution.keys())]

    # --- Compute correlation with English ---
    normal_vals = list(normal_distribution.values())
    mean1 = sum(normal_vals) / 26
    mean2 = sum(rel_freqs) / 26
    numerator = sum((a-mean1)*(b-mean2) for a, b in zip(normal_vals, rel_freqs))
    denominator = math.sqrt(sum((a-mean1)**2 for a in normal_vals) * sum((b-mean2)**2 for b in rel_freqs))
    corr = numerator / denominator if denominator else 0

    # --- Compute Index of Coincidence ---
    ic = sum(v*(v-1) for v in freq.values()) / (n*(n-1)) if n > 1 else 0

    # --- Identify likely cipher type ---
    if corr > 0.85:
        cipher_type = "Transposition (letter order changed, frequencies intact)"
    elif 0.5 <= corr <= 0.85 and ic >= 0.055:
        cipher_type = "Monoalphabetic Substitution (Caesar, Affine, etc.)"
    elif ic < 0.055 or corr < 0.5:
        cipher_type = "Polyalphabetic Substitution (Vigenère or similar)"
    else:
        cipher_type = "Uncertain — possibly mixed or short text"

    # --- Common n-grams ---
    ngrams = []
    for ngram_len in [3, 2]:
        subs = Counter(message[i:i+ngram_len] for i in range(len(message)-ngram_len+1))
        top = sorted(subs.items(), key=lambda x: x[1], reverse=True)[:10]
        ngrams.append(top)

    trigrams, bigrams = ngrams
    return trigrams, bigrams, freq_dist, cipher_type
