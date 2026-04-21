from itertools import permutations
import re

common_words = [
    "the","be","to","of","and","a","in","that","have","it","for",
    "not","on","with","he","as","you","do","at","this","but","his",
    "by","from","they","we","say","her","she","or","an","will","my",
    "one","all","would","there","their","what","so","up","out","if",
    "about","who","get","which","go","me","when","make","can","like",
    "no","just","him","know","take","into","your","good","some",
    "could","them","see","other","than","then","now","look","only",
    "come","its","over","think","also","back","after","use","two",
    "how","our","work","first","way","even","new","want",
    "because","any","these","give","day","most","us","is","are",
    "was","were","been","has","more","many","those"
]

english_frequencies = {
    "a": 0.08167, "b": 0.01492, "c": 0.02782, "d": 0.04253, "e": 0.12702,
    "f": 0.02228, "g": 0.02015, "h": 0.06094, "i": 0.06966, "j": 0.00153,
    "k": 0.00772, "l": 0.04025, "m": 0.02406, "n": 0.06749, "o": 0.07507,
    "p": 0.01929, "q": 0.00095, "r": 0.05987, "s": 0.06327, "t": 0.09056,
    "u": 0.02758, "v": 0.00978, "w": 0.02360, "x": 0.00150, "y": 0.01974,
    "z": 0.00074,
}

alphabet = "abcdefghijklmnopqrstuvwxyz"


def normalize(s):
    return ''.join(ch.upper() for ch in s if ch.isalpha())


def restore_format(original_message, decoded_message):
    restored = []
    letter_index = 0

    for ch in original_message:
        if ch.isalpha():
            new_char = decoded_message[letter_index]
            restored.append(new_char.upper() if ch.isupper() else new_char.lower())
            letter_index += 1
        else:
            restored.append(ch)

    return ''.join(restored)


def cell_size(r, c, convention):
    a, b = convention
    return a if (r + c) % 2 == 0 else b


def amsco_decode(ciphertext, key, convention=(1, 2)):
    ct = normalize(ciphertext)
    c_count = len(key)
    n = len(ct)

    if not c_count or not n:
        return ''

    sizes = []
    total = 0
    r = 0

    while total < n:
        row = [0] * c_count
        for c in range(c_count):
            if total >= n:
                break
            size = cell_size(r, c, convention)
            if total + size > n:
                size = n - total
            row[c] = size
            total += size
        sizes.append(row)
        r += 1

    row_count = len(sizes)
    col_len = [sum(sizes[rr][cc] for rr in range(row_count)) for cc in range(c_count)]

    read_order = sorted(range(c_count), key=lambda i: key[i])
    cols = [''] * c_count
    pos = 0

    for idx in read_order:
        cols[idx] = ct[pos:pos + col_len[idx]]
        pos += col_len[idx]

    col_pos = [0] * c_count
    out = []

    for rr in range(row_count):
        for cc in range(c_count):
            size = sizes[rr][cc]
            if size:
                out.append(cols[cc][col_pos[cc]:col_pos[cc] + size])
                col_pos[cc] += size

    return ''.join(out)


def chi_squared_score(text):
    text = ''.join(i for i in text.lower() if i.isalpha())
    n = len(text)

    if n == 0:
        return float("inf")

    score = 0.0
    for letter in alphabet:
        observed = text.count(letter)
        expected = english_frequencies[letter] * n
        score += ((observed - expected) ** 2) / expected

    return score


def whole_word_score(text):
    words = re.findall(r"[a-zA-Z]+", text.lower())
    return sum(1 for word in words if word in common_words)


def amsco_break(message, min_key_len=2, max_key_len=7):
    original_message = message
    cleaned = ''.join(i for i in message if i.isalpha())

    if len(cleaned) == 0:
        return "key: (), convention: (1, 2)", original_message

    candidates = []
    conventions = [(1, 2), (2, 1)]

    for key_length in range(min_key_len, max_key_len + 1):
        for perm_zero in permutations(range(key_length)):
            #convert 0-based permutation to rank-style key like [3,1,2]
            key = [0] * key_length
            for rank, col_index in enumerate(perm_zero, start=1):
                key[col_index] = rank

            for convention in conventions:
                decoded = amsco_decode(cleaned, key, convention)
                restored_candidate = restore_format(original_message, decoded)

                word_score = whole_word_score(restored_candidate)
                chi_score = chi_squared_score(decoded)

                #more words is better, lower chi is better
                ranking = (-word_score, chi_score)
                candidates.append((ranking, decoded, key, convention))

    candidates.sort(key=lambda x: x[0])
    best_ranking, final_msg, final_key, final_convention = candidates[0]

    restored_text = restore_format(original_message, final_msg)
    key_string = f"{tuple(final_key)}, convention: {final_convention}"

    return key_string, restored_text