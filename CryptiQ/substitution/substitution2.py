frequent_letters = [
    "e",
    "t",
    "a",
    "o",
    "i",
    "n",
    "s",
    "h",
    "r",
    "d",
    "l",
    "c",
    "u",
    "m",
    "f",
    "w",
    "g",
    "y",
    "p",
    "b",
    "v",
    "k",
    "j",
    "x",
    "q",
    "z",
]
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


def substitution_decode(message):
    message = message.replace(" ", "")
    letter_commonality = []
    for i in frequent_letters:
        letter_commonality.append((message.count(i.upper()), i.upper()))
    letter_commonality.sort(key=lambda x: x[0], reverse=True)
    ngram = 3
    for i in range(3):

        mode_string = ""
        frequency = 1
        nospace = message.replace(" ", "")
        substrings = []
        encrypted_alphabet = ["" for i in range(26)]
        for i in range(len(nospace) - (ngram - 1)):

            substring = nospace[i : i + ngram]
            if nospace.count(substring) > 1:
                substrings.append((nospace.count(substring), substring))
        substrings = list(set(substrings))
        substrings.sort(key=lambda x: x[0], reverse=True)
        print(substrings[:10])
        print()
        ngram -= 1

    print()
    print(letter_commonality)

    for index, i in enumerate(letter_commonality):
        message = message.replace(i[1], frequent_letters[index])
    encrypted_alphabet = []
    for index, i in enumerate(letter_commonality):
        encrypted_alphabet.append((frequent_letters[index], i[1]))
    true_encrypted_alphabet = []
    encrypted_alphabet.sort(key=lambda x: x[0])
    print()
    print(encrypted_alphabet)
    print()
    print(message)


substitution_decode(depunctuate(input("Enter message: ")))
