import re

COMMON_WORDS = [
    "the","be","to","of","and","a","in","that","have","i","it","for","not","on","with",
    "he","as","you","do","at","this","but","his","by","from","they","we","say","her",
    "she","or","an","will","my","one","all","would","there","their","what","so","up",
    "out","if","about","who","get","which","go","me","when","make","can","like","no",
    "just","him","know","take","into","your","good","some","could","them","see","other",
    "than","then","now","look","only","come","its","over","think","also","back","after",
    "use","two","how","our","work","first","well","way","even","new","want","because",
    "any","these","give","day","most","us",
]

ENGLISH_IOC_NORM = 1.73  # normalized IoC (26 * raw IoC)

def clean_alpha_lower(s: str) -> str:
    return "".join(ch for ch in s.lower() if "a" <= ch <= "z")

def index_of_coincidence_norm(text: str) -> float:
    # normalized IoC: 26 * sum(n_i(n_i-1)) / (N(N-1))
    counts = [0] * 26
    N = 0
    for ch in text:
        if "a" <= ch <= "z":
            counts[ord(ch) - 97] += 1
            N += 1
    if N < 2:
        return 0.0
    numer = sum(c * (c - 1) for c in counts)
    return 26.0 * numer / (N * (N - 1))

def caesar_shift(text: str, shift: int) -> str:
    # shift forward by `shift`
    out = []
    for ch in text:
        out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
    return "".join(out)

def wordish_score(s: str) -> int:
    # simple substring scoring; consistent with no-spaces strings
    return sum(s.count(w) for w in COMMON_WORDS)

def caesar_break(message: str):
    original = message
    cleaned = clean_alpha_lower(message)

    if not cleaned:
        return 0, original

    candidates = []
    for shift in range(26):
        decoded = caesar_shift(cleaned, shift)
        score_words = wordish_score(decoded)
        ioc = index_of_coincidence_norm(decoded)
        # primary: closeness to English IoC, secondary: word score (higher better)
        candidates.append((abs(ENGLISH_IOC_NORM - ioc), -score_words, shift, decoded, ioc))

    candidates.sort()
    best = candidates[0]
    best_shift = best[2]
    best_decoded = best[3]

    # restore punctuation + case into original layout
    restored = []
    j = 0
    for ch in original:
        if ch.isalpha():
            new = best_decoded[j]
            restored.append(new.upper() if ch.isupper() else new)
            j += 1
        else:
            restored.append(ch)

    return best_shift, "".join(restored)
