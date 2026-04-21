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


def get_decode_map(extended=False):
    if not extended:
        #classic 24-letter baconian
        return {
            'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D',
            'AABAA': 'E', 'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H',
            'ABAAA': 'I', 'ABAAB': 'K', 'ABABA': 'L', 'ABABB': 'M',
            'ABBAA': 'N', 'ABBAB': 'O', 'ABBBA': 'P', 'ABBBB': 'Q',
            'BAAAA': 'R', 'BAAAB': 'S', 'BAABA': 'T', 'BAABB': 'U',
            'BABAA': 'W', 'BABAB': 'X', 'BABBA': 'Y', 'BABBB': 'Z',
        }

    #extended 26-letter
    return {
        ''.join('B' if (i >> b) & 1 else 'A' for b in range(4, -1, -1)): chr(ord('A') + i)
        for i in range(26)
    }


def normalize_binary(text):
    #keep only a/b, or convert 0->a and 1->b
    out = []
    for ch in text:
        u = ch.upper()
        if u in ("A", "B"):
            out.append(u)
        elif ch == "0":
            out.append("A")
        elif ch == "1":
            out.append("B")
    return ''.join(out)


def case_to_binary(text):
    #upper=b, lower=a
    out = []
    for ch in text:
        if ch.isupper():
            out.append("B")
        elif ch.islower():
            out.append("A")
    return ''.join(out)


def decode_bits(bits, extended=False):
    table = get_decode_map(extended)
    decoded = []

    for i in range(0, len(bits), 5):
        group = bits[i:i+5]
        if len(group) < 5:
            break
        decoded.append(table.get(group, "?"))

    return ''.join(decoded)


def score_text(text):
    lowered = text.lower()
    return sum(lowered.count(word) for word in common_words)


def restore_format(original_message, decoded_message):
    #for baconian, decoded text is usually shorter than original cover text
    #so only restore case/punctuation if the original itself was basically a/b-like
    restored = []
    letter_index = 0

    for ch in original_message:
        if ch.isalpha() and letter_index < len(decoded_message):
            new_char = decoded_message[letter_index]
            restored.append(new_char.upper() if ch.isupper() else new_char.lower())
            letter_index += 1
        elif ch.isalpha():
            break
        else:
            restored.append(ch)

    if len(restored) == 0 or len(decoded_message) != sum(1 for ch in original_message if ch.isalpha()):
        return decoded_message

    return ''.join(restored)


def baconian_break(message):
    original_message = message

    candidates = []

    #mode 1: direct a/b or 0/1 input
    bits_ab = normalize_binary(message)
    if len(bits_ab) >= 5:
        for extended in (False, True):
            decoded = decode_bits(bits_ab, extended)
            probability = score_text(decoded)
            key = "extended 26-letter" if extended else "classic 24-letter"
            candidates.append((probability, decoded, key))

    #mode 2: hidden by case
    bits_case = case_to_binary(message)
    if len(bits_case) >= 5:
        for extended in (False, True):
            decoded = decode_bits(bits_case, extended)
            probability = score_text(decoded)
            key = f'{"extended 26-letter" if extended else "classic 24-letter"} using case mode'
            candidates.append((probability, decoded, key))

    if not candidates:
        return "No Baconian pattern detected", original_message

    candidates.sort(key=lambda x: x[0], reverse=True)
    best_score, final_msg, final_key = candidates[0]

    restored_text = restore_format(original_message, final_msg)

    return final_key, restored_text