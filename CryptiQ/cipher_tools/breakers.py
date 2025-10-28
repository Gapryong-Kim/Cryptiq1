"""
Extra Cipher Breakers for The Cipher Lab
---------------------------------------
Implements non-key or pattern-based breakers
compatible with the existing /breaker route.
Each returns (key, plaintext).
"""

import base64
import binascii
import re


# ==========================
#  ATBASH
# ==========================
def atbash_break(text: str):
    """Atbash simply mirrors the alphabet, no key."""
    result = ''.join(
        chr(155 - ord(ch)) if ch.isupper() else
        chr(219 - ord(ch)) if ch.islower() else ch
        for ch in text
    )
    return (None, result)


# ==========================
#  BASE64
# ==========================
def base64_break(text: str):
    """Decode Base64 automatically."""
    try:
        decoded = base64.b64decode(text.encode()).decode(errors="ignore")
        return (None, decoded.strip())
    except Exception:
        return (None, "Invalid Base64 input.")


# ==========================
#  HEXADECIMAL
# ==========================
def hex_break(text: str):
    """Convert hexadecimal to ASCII if valid."""
    text = text.strip().replace(" ", "")
    try:
        decoded = bytes.fromhex(text).decode(errors="ignore")
        return (None, decoded.strip())
    except Exception:
        return (None, "Invalid hexadecimal input.")


# ==========================
#  BINARY
# ==========================
def binary_break(text: str):
    """Convert binary (8-bit groups) to ASCII."""
    bits = re.findall(r"[01]{8}", text.replace(" ", ""))
    if not bits:
        return (None, "No valid binary sequence found.")
    try:
        decoded = ''.join(chr(int(b, 2)) for b in bits)
        return (None, decoded)
    except Exception:
        return (None, "Invalid binary sequence.")


import re

def baconian_break(cipher: str):
    """
    Fully automatic Baconian breaker.
    Handles:
      - A/B 5-bit text or upper/lower case encoding
      - 24-letter or 26-letter alphabet
      - Reversed (A↔B) mappings
    Returns (None, plaintext) in lowercase.
    """

    # --- Extract raw A/B pattern ---
    text = cipher.upper().replace(" ", "")
    bits = re.sub(r"[^AB]", "", text)

    if not bits:
        # Maybe it's upper/lower encoding (A=upper, B=lower)
        bits = ''.join('A' if c.isupper() else 'B' for c in cipher if c.isalpha())

    if not bits:
        return (None, "no valid baconian pattern detected.")

    # --- Baconian dictionaries ---
    BACON_24 = {
        'AAAAA':'A','AAAAB':'B','AAABA':'C','AAABB':'D','AABAA':'E',
        'AABAB':'F','AABBA':'G','AABBB':'H','ABAAA':'I','ABAAB':'K',
        'ABABA':'L','ABABB':'M','ABBAA':'N','ABBAB':'O','ABBBA':'P',
        'ABBBB':'Q','BAAAA':'R','BAAAB':'S','BAABA':'T','BAABB':'U',
        'BABAA':'W','BABAB':'X','BABBA':'Y','BABBB':'Z'
    }

    BACON_26 = {
        'AAAAA':'A','AAAAB':'B','AAABA':'C','AAABB':'D','AABAA':'E',
        'AABAB':'F','AABBA':'G','AABBB':'H','ABAAA':'I','ABAAB':'J',
        'ABABA':'K','ABABB':'L','ABBAA':'M','ABBAB':'N','ABBBA':'O',
        'ABBBB':'P','BAAAA':'Q','BAAAB':'R','BAABA':'S','BAABB':'T',
        'BABAA':'U','BABAB':'V','BABBA':'W','BABBB':'X','BBAAA':'Y',
        'BBAAB':'Z'
    }

    # --- Decode helper ---
    def decode(bits, mapping):
        decoded = []
        for i in range(0, len(bits), 5):
            chunk = bits[i:i+5]
            if len(chunk) == 5:
                decoded.append(mapping.get(chunk, '?'))
        return ''.join(decoded)

    # --- Flipped (A↔B) version ---
    flipped = bits.replace('A', 'x').replace('B', 'A').replace('x', 'B')

    # --- Generate all possible decoded texts ---
    variants = {
        "24-normal": decode(bits, BACON_24),
        "26-normal": decode(bits, BACON_26),
        "24-flipped": decode(flipped, BACON_24),
        "26-flipped": decode(flipped, BACON_26),
    }

    # --- English-likeness heuristic ---
    def score_english(txt):
        vowels = sum(ch in "AEIOU" for ch in txt)
        letters = sum(ch.isalpha() for ch in txt)
        if not letters:
            return 0
        vowel_ratio = vowels / letters
        space_ratio = txt.count(' ') / max(len(txt), 1)
        long_seq = len(re.findall(r"[AEIOU]{2,}", txt))  # extra boost if vowels cluster
        return vowel_ratio + (0.5 * space_ratio) + (0.2 * long_seq)

    # --- Score all versions ---
    best_variant = max(variants.items(), key=lambda kv: score_english(kv[1]))

    # Return lowercase decoded plaintext
    return (None, best_variant[1].lower())

# ==========================
#  AUTO-DETECT WRAPPER
# ==========================
def auto_break(text: str):
    """
    Tries all simple ciphers (non-key ones) and returns a dict of results.
    Useful for your 'Try All' feature.
    """
    results = {}
    for func in [atbash_break, base64_break, hex_break, binary_break, baconian_break]:
        name = func.__name__.replace("_break", "").title()
        key, pt = func(text)
        results[name] = {"key": key, "plaintext": pt}
    return results


# ==========================
#  Quick test
# ==========================
if __name__ == "__main__":
    samples = {
        "Atbash": "Uryyb Jbeyq",
        "Base64": "SGVsbG8gV29ybGQ=",
        "Hex": "48656c6c6f20576f726c64",
        "Binary": "01001000 01100101 01101100 01101100 01101111",
        "Baconian": "AAAAA AABAA ABBBA"
    }

    for name, val in samples.items():
        func = globals().get(f"{name.lower()}_break")
        if func:
            print(f"[{name}] ->", func(val))
