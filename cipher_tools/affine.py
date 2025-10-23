
common_words = [
    "the",
    "be",
    "to",
    "of",
    "and",
    "a",
    "in",
    "that",
    "have",
    "I",
    "it",
    "for",
    "not",
    "on",
    "with",
    "he",
    "as",
    "you",
    "do",
    "at",
    "this",
    "but",
    "his",
    "by",
    "from",
    "they",
    "we",
    "say",
    "her",
    "she",
    "or",
    "an",
    "will",
    "my",
    "one",
    "all",
    "would",
    "there",
    "their",
    "what",
    "so",
    "up",
    "out",
    "if",
    "about",
    "who",
    "get",
    "which",
    "go",
    "me",
    "when",
    "make",
    "can",
    "like",
    "no",
    "just",
    "him",
    "know",
    "take",
    "into",
    "your",
    "good",
    "some",
    "could",
    "them",
    "see",
    "other",
    "than",
    "then",
    "now",
    "look",
    "only",
    "come",
    "its",
    "over",
    "think",
    "also",
    "back",
    "after",
    "use",
    "two",
    "how",
    "our",
    "work",
    "first",
    "well",
    "way",
    "even",
    "new",
    "want",
    "because",
    "any",
    "these",
    "give",
    "day",
    "most",
    "us",
]


def depunctuate(msg):
    depunctuated_message = ""
    punctuation = [
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        "!",
        '"',
        "#",
        "$",
        "%",
        "&",
        "'",
        "(",
        ")",
        "*",
        "+",
        ",",
        "-",
        ".",
        "/",
        ":",
        ";",
        "<",
        "=",
        ">",
        "?",
        "@",
        "[",
        "\\",
        "]",
        "^",
        "_",
        "`",
        "{",
        "|",
        "}",
        "~",
        "'",
        "’",
    ]
    for i in msg:
        if i not in punctuation:
            depunctuated_message += i
    return depunctuated_message





alphabet = [
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
]


def affine_break(message):
    original_message = message
    message=''.join(i for i in message if i.isalpha()).lower()
    coprimes = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    inverse_mod = [1, 9, 21, 15, 3, 19, 7, 23, 11, 5, 17, 25]
    decoded_messages = []
    probabilities = []

    for a in coprimes:
        mod_inv = inverse_mod[coprimes.index(a)]
        for b in range(26):
            decoded = ""
            for z in message:
                if z != " ":
                    current_index = alphabet.index(z)
                    decoded_index = (mod_inv * (current_index - b)) % 26
                    letter = alphabet[decoded_index]
                else:
                    letter = " "
                decoded += letter
            probability = 0
            split = decoded.split()
            probability = sum(decoded.count(i) for i in common_words)
            data = (probability, decoded,(a,b))

            decoded_messages.append(data,)
    final_prob = 0
    for likelihood, msg,key in decoded_messages:
        if likelihood > final_prob:
            final_prob = likelihood
            final_msg = msg
            final_key=key
    a=final_key[0]
    b=final_key[1]
    final_key=f"a = {a}, b={b}"
    restored = []
    letter_index = 0
    for ch in original_message:
        if ch.isalpha():
            # Preserve original case
            new_char = final_msg[letter_index]
            restored.append(new_char.upper() if ch.isupper() else new_char)
            letter_index += 1
        else:
            restored.append(ch)
    restored_text = ''.join(restored)
    
    return final_key,restored_text


def affine_encode():
    key = input("Enter key(ax+b):")
    print(key)
    message = input("Enter message:")
    encoded_message = ""
    for i in message:
        if i != " ":
            index = alphabet.index(i)
        equation = ""

        for x in key:

            if x != "x":
                equation += x
            #   print(equation)
            elif x == "x":
                equation += f"*{index}"
            #   print(equation)
        if i != " ":
            new_index = eval(equation) % 26
            encoded_message += alphabet[new_index]
        else:
            encoded_message += " "
    print(encoded_message)


