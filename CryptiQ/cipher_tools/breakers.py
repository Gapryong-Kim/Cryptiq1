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
