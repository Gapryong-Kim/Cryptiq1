# cipher_tools/encoders.py
import base64
import string

# ==============================
#  Common alphabet + utilities
# ==============================
ALPHABET = string.ascii_uppercase
ALPHA_LEN = len(ALPHABET)

def clean_text(text):
    return ''.join(ch for ch in text.upper() if ch.isalpha())


# ==============================
#  CAESAR
# ==============================
def caesar_encode(text, shift=3):
    result = []
    for ch in text:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            result.append(chr((ord(ch) - ord(base) + shift) % 26 + ord(base)))
        else:
            result.append(ch)
    return ''.join(result)

def caesar_decode(text, shift=3):
    return caesar_encode(text, -shift)


# ==============================
#  VIGENERE
# ==============================
def vigenere_encode(text, key):
    result, key = [], key.upper()
    ki = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            base = 'A' if ch.isupper() else 'a'
            result.append(chr((ord(ch) - ord(base) + shift) % 26 + ord(base)))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

def vigenere_decode(text, key):
    result, key = [], key.upper()
    ki = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            base = 'A' if ch.isupper() else 'a'
            result.append(chr((ord(ch) - ord(base) - shift) % 26 + ord(base)))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)


# ==============================
#  AFFINE
# ==============================
def affine_encode(text, a=5, b=8):
    result = []
    for ch in text.upper():
        if ch in ALPHABET:
            x = ALPHABET.index(ch)
            result.append(ALPHABET[(a * x + b) % ALPHA_LEN])
        else:
            result.append(ch)
    return ''.join(result)

def affine_decode(text, a=5, b=8):
    a_inv = pow(a, -1, ALPHA_LEN)
    result = []
    for ch in text.upper():
        if ch in ALPHABET:
            y = ALPHABET.index(ch)
            result.append(ALPHABET[(a_inv * (y - b)) % ALPHA_LEN])
        else:
            result.append(ch)
    return ''.join(result)


# ==============================
#  ATBASH
# ==============================
def atbash_encode(text):
    return ''.join(
        chr(155 - ord(ch)) if ch.isupper() else
        chr(219 - ord(ch)) if ch.islower() else ch
        for ch in text
    )

def atbash_decode(text):
    return atbash_encode(text)


# ==============================
#  RAIL FENCE
# ==============================
def railfence_encode(text, rails, offset=0):
    if rails <= 1 or rails >= len(text):
        return text

    # normalize offset to cycle length
    cycle = 2 * rails - 2
    offset = int(offset) % cycle if cycle else 0

    rail = [''] * rails
    row = 0
    direction = 1  # 1 down, -1 up

    # advance the zig-zag state by `offset` steps (without placing chars)
    for _ in range(offset):
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    for ch in text:
        rail[row] += ch

        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    return ''.join(rail)

def railfence_decode(cipher, rails=3, offset=0):
    if rails <= 1 or rails >= len(cipher):
        return cipher

    n = len(cipher)
    cycle = 2 * rails - 2
    offset = int(offset) % cycle if cycle else 0

    # Step 1: build the zig-zag pattern (row index for each char)
    pattern = []
    row = 0
    direction = 1

    # advance zig-zag by offset (no chars placed yet)
    for _ in range(offset):
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    for _ in range(n):
        pattern.append(row)

        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    # Step 2: determine how many characters go in each rail
    rail_counts = [0] * rails
    for r in pattern:
        rail_counts[r] += 1

    # Step 3: split ciphertext into rails
    rails_content = []
    idx = 0
    for count in rail_counts:
        rails_content.append(list(cipher[idx:idx + count]))
        idx += count

    # Step 4: rebuild plaintext following the pattern
    rail_pos = [0] * rails
    result = []

    for r in pattern:
        result.append(rails_content[r][rail_pos[r]])
        rail_pos[r] += 1

    return ''.join(result)


# ==============================
#  COLUMNAR TRANSPOSITION
# ==============================
def columnar_encode(text, key):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    columns = [''] * len(key)
    for i, ch in enumerate(text):
        columns[i % len(key)] += ch
    return ''.join(columns[k] for k in key_order)

def columnar_decode(cipher, key):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    n = len(cipher)
    cols = len(key)
    rows = n // cols + (n % cols != 0)
    col_lengths = [rows if i < n % cols else rows - 1 for i in range(cols)]
    col_data, index = {}, 0
    for i, k in enumerate(key_order):
        col_data[k] = cipher[index:index + col_lengths[i]]
        index += col_lengths[i]
    plaintext = ''
    for r in range(rows):
        for c in range(cols):
            if r < len(col_data[c]):
                plaintext += col_data[c][r]
    return plaintext

# ==============================
#  POLYBIUS (Customizable Grid)
# ==============================
def generate_polybius_square(key=None):
    """
    Generate a Polybius 5x5 grid. If a custom key is provided (25 letters),
    it defines the grid order; otherwise defaults to the standard one.
    The letter J is merged with I.
    """
    base = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 25 letters (I/J merged)
    if key:
        key = ''.join(ch for ch in key.upper() if ch.isalpha())
        key = key.replace("J", "I")
        seen = set()
        ordered = []
        for ch in key + base:
            if ch not in seen and len(ordered) < 25:
                seen.add(ch)
                ordered.append(ch)
        letters = ordered
    else:
        letters = list(base)

    # build coordinate mapping
    square = {}
    index = 0
    for r in range(1, 6):
        for c in range(1, 6):
            square[letters[index]] = f"{r}{c}"
            index += 1
    return square


def polybius_encode(text, key=None):
    """
    Encode plaintext using a (possibly custom) Polybius square.
    Non-letter characters are preserved.
    """
    grid = generate_polybius_square(key)
    result = []
    for ch in text:
        up = ch.upper()
        if up in grid:
            result.append(grid[up])
        else:
            result.append(ch)
    return ' '.join(result)


def polybius_decode(cipher, key=None):
    """
    Decode Polybius coordinates (11–55) using a (possibly custom) grid.
    Non-digit chunks are left untouched.
    """
    grid = generate_polybius_square(key)
    inv = {v: k for k, v in grid.items()}
    parts = cipher.strip().replace("\n", " ").split()

    result = []
    for p in parts:
        result.append(inv.get(p, p))
    return ''.join(result)


# ==============================
#  BASE64 / HEX / BINARY
# ==============================
def base64_encode(text):
    return base64.b64encode(text.encode()).decode()

def base64_decode(text):
    return base64.b64decode(text.encode()).decode(errors='ignore')

def hex_encode(text):
    return text.encode().hex()

def hex_decode(text):
    try:
        return bytes.fromhex(text).decode()
    except:
        return "Invalid hex input."

def binary_encode(text):
    return ' '.join(format(ord(c), '08b') for c in text)

def binary_decode(text):
    try:
        return ''.join(chr(int(b, 2)) for b in text.split())
    except:
        return "Invalid binary input."


# ==============================
#  PERMUTATION (simple key map)
# ==============================
def permutation_encode(text, key):
    key_map = {ALPHABET[i]: key[i].upper() for i in range(26)}
    return ''.join(key_map.get(ch.upper(), ch) if ch.isalpha() else ch for ch in text)

def permutation_decode(text, key):
    rev_map = {key[i].upper(): ALPHABET[i] for i in range(26)}
    return ''.join(rev_map.get(ch.upper(), ch) if ch.isalpha() else ch for ch in text)


# ==============================
#  AMSCO
# ==============================
def amsco_encode(text, key):
    text = text.replace(" ", "")
    ncols = len(key)
    pattern = []
    toggle = 1
    i = 0
    while i < len(text):
        for _ in range(ncols):
            size = 1 if toggle else 2
            pattern.append(size)
            i += size
            if i >= len(text): break
        toggle = not toggle

    grid = [''] * ncols
    i = 0
    for col_size in pattern[:len(text)]:
        col = i % ncols
        grid[col] += text[i:i+col_size]
        i += col_size

    key_order = sorted(range(len(key)), key=lambda k: key[k])
    return ''.join(grid[i] for i in key_order)

def amsco_decode(cipher, key):
    ncols = len(key)
    key_order = sorted(range(ncols), key=lambda k: key[k])
    rows = len(cipher) // ncols
    col_length = [rows] * ncols
    extra = len(cipher) % ncols
    for i in range(extra):
        col_length[key_order[i]] += 1
    cols, index = [''] * ncols, 0
    for k in key_order:
        cols[k] = cipher[index:index + col_length[k]]
        index += col_length[k]
    plaintext = ''
    for i in range(rows + 1):
        for c in range(ncols):
            if i < len(cols[c]):
                plaintext += cols[c][i]
    return plaintext


# ==============================
#  BACONIAN
# ==============================
BACON_DICT = {
    'A': 'AAAAA','B': 'AAAAB','C': 'AAABA','D': 'AAABB','E': 'AABAA',
    'F': 'AABAB','G': 'AABBA','H': 'AABBB','I': 'ABAAA','J': 'ABAAB',
    'K': 'ABABA','L': 'ABABB','M': 'ABBAA','N': 'ABBAB','O': 'ABBBA',
    'P': 'ABBBB','Q': 'BAAAA','R': 'BAAAB','S': 'BAABA','T': 'BAABB',
    'U': 'BABAA','V': 'BABAB','W': 'BABBA','X': 'BABBB','Y': 'BBAAA',
    'Z': 'BBAAB'
}
def baconian_encode(text):
    return ' '.join(BACON_DICT.get(ch.upper(), ch) for ch in text if ch.isalpha())

def baconian_decode(cipher):
    inv = {v: k for k, v in BACON_DICT.items()}
    blocks = cipher.replace(" ", "")
    decoded = ""
    for i in range(0, len(blocks), 5):
        chunk = blocks[i:i+5]
        decoded += inv.get(chunk, "")
    return decoded
    
print(railfence_encode("WEAREDISCOVEREDFLEEATONCE", 4))
