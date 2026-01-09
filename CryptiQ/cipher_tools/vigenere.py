"""
Adaptive Vigenère breaker implementing:
  Method 1: Brute force (short keys only)
  Method 4: Variational / hill-climbing optimization
  Method 5: Statistics-only attack (IoC + frequency matching)

Based on "Five Ways to Crack a Vigenère Cipher" by The Mad Doctor.
"""

from __future__ import annotations
from dataclasses import dataclass
from itertools import product
from math import sqrt
from random import randrange
from typing import List, Optional
import re

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A2I = {c: i for i, c in enumerate(ALPHABET)}
I2A = {i: c for i, c in enumerate(ALPHABET)}

# English monogram frequencies (normalized)
EN_FREQ = [
    0.08167,0.01492,0.02782,0.04253,0.12702,0.02228,0.02015,0.06094,0.06966,
    0.00153,0.00772,0.04025,0.02406,0.06749,0.07507,0.01929,0.00095,0.05987,
    0.06327,0.09056,0.02758,0.00978,0.02360,0.00150,0.01974,0.00074
]

# ------------------ Helpers ------------------

def clean(text: str) -> str:
    return "".join(c for c in text.upper() if c.isalpha())

def decrypt(cipher: str, key: str) -> str:
    out = []
    for i, c in enumerate(cipher):
        out.append(I2A[(A2I[c] - A2I[key[i % len(key)]]) % 26])
    return "".join(out)

def restore(original: str, letters: str) -> str:
    out, j = [], 0
    for c in original:
        if c.isalpha():
            out.append(letters[j].lower() if c.islower() else letters[j])
            j += 1
        else:
            out.append(c)
    return "".join(out)

# ------------------ Statistics ------------------

def index_of_coincidence(text: str) -> float:
    counts = [0]*26
    for c in text:
        counts[A2I[c]] += 1
    n = sum(counts)
    if n < 2:
        return 0.0
    return 26 * sum(c*(c-1) for c in counts) / (n*(n-1))

def cosangle(x, y):
    num = sum(a*b for a,b in zip(x,y))
    den = sqrt(sum(a*a for a in x)*sum(b*b for b in y))
    return num/den if den else 0.0

def slice_frequencies(text: str, period: int):
    slices = [""]*period
    for i,c in enumerate(text):
        slices[i % period] += c
    freqs = []
    for s in slices:
        f = [0]*26
        for c in s:
            f[A2I[c]] += 1
        total = len(s)
        freqs.append([x/total for x in f])
    return freqs

# ------------------ Method 5 ------------------

def stats_only(cipher: str) -> Optional[str]:
    # find likely period
    for p in range(1, 21):
        iocs = []
        slices = [""]*p
        for i,c in enumerate(cipher):
            slices[i % p] += c
        iocs = [index_of_coincidence(s) for s in slices]
        if sum(iocs)/p > 1.6:
            period = p
            break
    else:
        return None

    freqs = slice_frequencies(cipher, period)
    key = []
    for f in freqs:
        for shift in range(26):
            rotated = f[shift:] + f[:shift]
            if cosangle(EN_FREQ, rotated) > 0.9:
                key.append(I2A[shift])
                break
        else:
            key.append("A")
    return "".join(key)

# ------------------ Method 4 ------------------

def fitness(text: str) -> float:
    return sum(EN_FREQ[A2I[c]] for c in text) / len(text)

def variational(cipher: str, period: int) -> str:
    key = ["A"]*period
    best = fitness(decrypt(cipher, "".join(key)))
    improved = True
    while improved:
        improved = False
        for i in range(period):
            for c in ALPHABET:
                test = key[:]
                test[i] = c
                score = fitness(decrypt(cipher, "".join(test)))
                if score > best:
                    best = score
                    key = test
                    improved = True
    return "".join(key)

# ------------------ Method 1 ------------------

def brute_force(cipher: str, max_len=3) -> Optional[str]:
    for L in range(1, max_len+1):
        for k in product(ALPHABET, repeat=L):
            key = "".join(k)
            pt = decrypt(cipher, key)
            if fitness(pt) > 0.06:
                return key
    return None

# ------------------ Adaptive ------------------

@dataclass
class Result:
    key: str
    plaintext: str
    method: str

def break_vigenere(ciphertext: str) -> Result:
    clean_ct = clean(ciphertext)
    n = len(clean_ct)

    # Long text → method 5
    if n > 200:
        key = stats_only(clean_ct)
        if key:
            return Result(key, restore(ciphertext, decrypt(clean_ct, key)), "statistics-only")

    # Medium → method 4
    if n > 50:
        key = variational(clean_ct, 5)
        return Result(key, restore(ciphertext, decrypt(clean_ct, key)), "variational")

    # Short → method 1
    key = brute_force(clean_ct)
    if key:
        return Result(key, restore(ciphertext, decrypt(clean_ct, key)), "bruteforce")

    return Result("", ciphertext, "failed")

if __name__ == "__main__":
    ct = input("ciphertext: ")
    r = break_vigenere(ct)
    print("method:", r.method)
    print("key:", r.key)
    print("plaintext:", r.plaintext)
