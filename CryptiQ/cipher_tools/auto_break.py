"""
auto_break.py — Universal Cipher Auto-Detector for The Cipher Lab
-----------------------------------------------------------------
Runs frequency analysis first to classify as substitution or
transposition, then tests only relevant breakers + universal ones.
Prefers Caesar in close ties with Vigenere.
"""

import re
from datetime import datetime

# --- Breakers (keyed) ---
from cipher_tools.caesar import caesar_break
from cipher_tools.vigenere import break_vigenere
from cipher_tools.affine import affine_break
from cipher_tools.amsco import amsco_break
from cipher_tools.railfence import railfence_break
from cipher_tools.columnar_transposition import columnar_break
from cipher_tools.permutation import permutation_break
from cipher_tools.polybius_square import *  # ✅ make sure this path is correct

# --- Frequency analysis (for broad classification only) ---
from cipher_tools.frequency_analyser import analyse

# --- Non-key / universal ---
from cipher_tools.breakers import (
    atbash_break,
    base64_break,
    hex_break,
    binary_break,
    baconian_break,
)

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
def vigenere_auto(raw_text: str):
    r = break_vigenere(raw_text)   # your adaptive 1/4/5 breaker
    return r.key, r.plaintext


# ===============================
#  CANDIDATE FILTERING (avoid friendly failure strings winning)
# ===============================
FAIL_MARKERS = (
    "no valid binary", "not a valid binary", "invalid binary",
    "no valid base64", "invalid base64", "not valid base64",
    "no valid hex", "invalid hex", "not valid hex",
    "no valid bacon", "invalid bacon",
    "failed to decode", "unable to decode",
)

def _should_skip_candidate(name: str, raw_text: str, key, pt: str) -> bool:
    """Skip candidates that are clearly error messages or no-op decodes."""
    if not isinstance(pt, str):
        return True
    pt_stripped = pt.strip()
    if not pt_stripped:
        return True
    low = pt_stripped.lower()
    # Skip known decoder failure messages
    if any(m in low for m in FAIL_MARKERS):
        return True
    # For universal decoders: if output is identical to input, treat as no-op
    if name in {"Binary", "Base64", "Hex", "Baconian"}:
        if pt_stripped == (raw_text or "").strip():
            return True
    return False


def score_english(text: str) -> float:
    """Rates text by how 'English-like' it is."""
    if not isinstance(text, str) or not text.strip():
        return 0.0
    clean = text.strip()

    letters = sum(ch.isalpha() for ch in clean)
    spaces  = clean.count(" ")
    ratio   = (letters + spaces) / max(len(clean), 1)

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
    Runs frequency analysis (on a cleaned copy) to choose which ciphers to test.
    Returns dict {cipher, key, plaintext, score, broad_type}.
    """
    if not isinstance(text, str):
        text = str(text)

    raw_text = text  # ✅ keep original for breakers
    cleaned_for_freq = ''.join(ch for ch in raw_text.lower() if ch.isalpha())

    if not raw_text.strip():
        return {"cipher": "Unknown", "key": None, "plaintext": "", "score": 0.0, "broad_type": "Unknown"}

    # --- Step 1: Frequency analysis to classify broad type (uses cleaned alpha text only) ---
    try:
        # analyse returns: trigrams, bigrams, freq_dist, cipher_type (string)
        _, _, _, freq_hint = analyse(cleaned_for_freq or raw_text)
        if "Substitution" in freq_hint:
            broad_type = "Substitution"
        elif "Transposition" in freq_hint:
            broad_type = "Transposition"
        else:
            broad_type = "Unknown"
    except Exception:
        broad_type = "Unknown"

    # --- Step 2: Select relevant breakers ---
    if broad_type == "Substitution":
        cipher_funcs = [
            ("Caesar",      caesar_break),
            ("Vigenere",    vigenere_auto),
            ("Affine",      affine_break),
            ("Amsco",       amsco_break),
        ]
        # Optional substitution breaker (only if available in imports)
        if "substitution_break" in globals():
            cipher_funcs.append(("Substitution", substitution_break))
    elif broad_type == "Transposition":
        cipher_funcs = [
            ("Columnar",    columnar_break),
            ("Permutation", permutation_break),
            ("Railfence",   railfence_break),
        ]
    else:
        # Unknown → try a balanced set
        cipher_funcs = [
            ("Caesar",      caesar_break),
            ("Vigenere",    vigenere_auto),
            ("Columnar",    columnar_break),
            ("Railfence",   railfence_break),
            ("Affine",      affine_break),
        ]

    # Always include non-key ciphers (use raw_text so base64/hex/binary work)
    nonkey_funcs = [
        ("Atbash",   atbash_break),
        ("Base64",   base64_break),
        ("Hex",      hex_break),
        ("Binary",   binary_break),
        ("Baconian", baconian_break),
    ]

    all_funcs = cipher_funcs + nonkey_funcs

    # --- Step 3: Test selected ciphers ---
    candidates = {}
    for name, func in all_funcs:
        try:
            result = func(raw_text)  # ✅ keep original text
            if isinstance(result, (tuple, list)) and len(result) == 2:
                key, pt = result
            else:
                key, pt = None, str(result)
            if _should_skip_candidate(name, raw_text, key, pt):
                continue
            candidates[name] = (key, pt)
        except Exception:
            continue

    if not candidates:
        return {
            "cipher": "Unknown",
            "key": None,
            "plaintext": raw_text,
            "score": 0.0,
            "broad_type": broad_type,
        }

    # --- Step 4: Score and choose best ---
    scored = []
    for name, (key, plaintext) in candidates.items():
        s = score_english(plaintext)
        scored.append((name, key, plaintext, s))

    scored.sort(key=lambda x: x[3], reverse=True)
    best_name, best_key, best_text, best_score = scored[0]

    # --- Step 5: Prefer Caesar over Vigenere on very close ties ---
    if len(scored) > 1:
        second_name, _, _, second_score = scored[1]
        if {best_name, second_name} == {"Caesar", "Vigenere"} and abs(best_score - second_score) < 0.02:
            best_name = "Caesar"

    return {
        "cipher": best_name,
        "key": best_key,
        "plaintext": best_text,
        "score": round(best_score, 3),
        "broad_type": broad_type,
    }
