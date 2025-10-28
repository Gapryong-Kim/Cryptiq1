"""
auto_break.py — Universal Cipher Auto-Detector for The Cipher Lab
-----------------------------------------------------------------
Tests all known breakers (keyed + non-keyed) and picks the result
with the highest English-likeness score.
Prefers Caesar in close ties with Vigenere.
"""

from cipher_tools.vigenere import vigenere_break
from cipher_tools.caesar import caesar_break
from cipher_tools.permutation import permutation_break
from cipher_tools.columnar_transposition import columnar_break
from cipher_tools.frequency_analyser import analyse
from cipher_tools.affine import affine_break
from cipher_tools.amsco import amsco_break
from cipher_tools.railfence import railfence_break
from cipher_tools.polybius_square import *
from utility.unique import unique


from datetime import datetime
from cipher_tools.breakers import (
            atbash_break,
            base64_break,
            hex_break,
            binary_break,
            baconian_break)
# ===============================
#  ENGLISH SCORING HELPER
# ===============================
COMMON_WORDS = {
    "the","be","to","of","and","a","in","that","have","i","it","for","not","on",
    "with","he","as","you","do","at","this","but","his","by","from","they","we",
    "say","her","she","or","an","will","my","one","all","would","there","their",
    "what","so","up","out","if","about","who","get","which","go","me","when",
    "make","can","like","time","no","just","him","know","take","people","into",
    "year","your","good","some"
}

def score_english(text: str) -> float:
    """Rates text by how 'English-like' it is."""
    if not text or not isinstance(text, str):
        return 0.0
    clean = text.strip()
    if not clean:
        return 0.0

    letters = sum(ch.isalpha() for ch in clean)
    spaces = clean.count(" ")
    ratio = (letters + spaces) / max(len(clean), 1)

    words = re.findall(r"[A-Za-z]+", clean.lower())
    matches = sum(1 for w in words if w in COMMON_WORDS)
    word_ratio = matches / max(len(words), 1)

    symbols = sum(1 for ch in clean if not (ch.isalnum() or ch.isspace() or ch in ",.?!'"))
    sym_penalty = 1 - min(symbols / max(len(clean), 1), 0.5)

    return (0.6 * ratio + 0.4 * word_ratio) * sym_penalty


# ===============================
#  AUTO-DETECT FUNCTION
# ===============================
def auto_break(text: str):
    """
    Try all breakers (keyed + non-keyed) and return the best guess.
    Prefers Caesar over Vigenere when scores are very close.
    """
    candidates = {}

    # --- Keyed ciphers ---
    for name, func in [
        ("Caesar", caesar_break),
        ("Vigenere", vigenere_break),
        ("Affine", affine_break),
        ("Amsco", amsco_break),
        ("Railfence", railfence_break),
        ("Columnar", columnar_break),
        ("Permutation", permutation_break),
        ("Substitution", substitution_break)
    ]:
        try:
            key, pt = func(text)
            candidates[name] = (key, pt)
        except Exception:
            pass

    # --- Non-key ciphers ---
    for func in [atbash_break, base64_break, hex_break, binary_break, baconian_break]:
        try:
            key, pt = func(text)
            name = func.__name__.replace("_break", "").title()
            candidates[name] = (key, pt)
        except Exception:
            continue

    # --- Score all results ---
    scored = []
    for name, (key, plaintext) in candidates.items():
        s = score_english(plaintext)
        scored.append((name, key, plaintext, s))

    if not scored:
        return {"cipher": "Unknown", "key": None, "plaintext": text, "score": 0.0}

    # Sort by score
    scored.sort(key=lambda x: x[3], reverse=True)
    best_name, best_key, best_text, best_score = scored[0]

    # --- Handle near-tie between Vigenere and Caesar ---
    if len(scored) > 1:
        second_name, _, _, second_score = scored[1]
        if (
            {best_name, second_name} == {"Caesar", "Vigenere"} and
            abs(best_score - second_score) < 0.02
        ):
            best_name = "Caesar"  # prefer Caesar in close tie

    return {
        "cipher": best_name,
        "key": best_key,
        "plaintext": best_text,
        "score": round(best_score, 3)
    }


