import nltk, random, pyperclip
from itertools import permutations



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
]


def depunctuate(msg):
    depunctuated_message = ""
    punctuation = [
        '–',
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


def is_english(word):
    if word.lower() in common_words:
        return True


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

# print(word_list)

decoded_possible = []


def caesar_decode(new_message):
    shift = 1
    probability = 0
    likelihood = []
    decoded_message = ""
    for h in range(25):
        for v, i in enumerate(new_message):

            for x in i:

                if (alphabet.index(x) - shift) >= 0:
                    decoded_message += alphabet[alphabet.index(x) - shift]

                else:
                    decoded_message += alphabet[alphabet.index(x) - shift]
            decoded_message += " "
        splitmessage = decoded_message.split()
        # print(splitmessage)
        for obj in splitmessage:
            if is_english(obj):
                probability += 1

        datatuple = (probability, decoded_message, shift)
        likelihood.append(datatuple)
        shift += 1
        decoded_message = ""
        most_likely = 0
        probability = 0
    for m, z, a in likelihood:
        if m > most_likely:
            most_likely = m
            decoded_message = z

    result = (most_likely, decoded_message)
    decoded_possible.append(result)
    probability = 0


def caesar_encode(new_message):
    encryption_key = int(input("Enter key: "))
    KEY = encryption_key
    encoded_message = ""
    for i in new_message:
        for x in i:
            x_index = alphabet.index(x)
            if x_index + encryption_key > 25:
                encryption_key -= len(alphabet) - x_index
                encoded_message += alphabet[encryption_key]
            else:

                encoded_message += alphabet[x_index + encryption_key]
            encryption_key = KEY
        encoded_message += " "
    print(encoded_message)


def atbash_decode(new_message):
    probability = 0
    decoded_message = ""
    for i in new_message:
        for x in i:
            if i == ".":
                next
            new_index = (alphabet.index(x) + 1) * -1
            decoded_message += alphabet[new_index]

        decoded_message += " "
    for i in decoded_message.split():
        if is_english(i):
            probability += 1
    result = (probability, decoded_message)
    decoded_possible.append(result)


def atbash_encode(new_message):
    new_sentence = ""

    for i in new_message:
        for x in i:
            new_index = (alphabet.index(x) + 1) * -1
            new_sentence += alphabet[new_index]
        new_sentence += " "

    print(new_sentence)


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


def permutation_decode(message):
    final_msgs = []
    for length in range(1, 8):

        perms = list(set(permutations(range(1, length + 1))))
        nospace = message.replace(" ", "")
        split_blocks = [nospace[i : i + length] for i in range(0, len(nospace), length)]
        decoded_msgs = []
        for perm in perms:
            decoded = ""
            for block in split_blocks:
                permuted_block = "".join(
                    block[i - 1] for i in perm if i - 1 < len(block)
                )
                decoded += permuted_block
            decoded_msgs.append(decoded)

        possibilities = []
        for decoded_msg in decoded_msgs:
            probability = sum(decoded_msg.count(word) for word in common_words)
            possibilities.append((probability, decoded_msg))

        final_prob = 0
        final_msg = ""
        for likelihood, msg in possibilities:
            if likelihood > final_prob:
                final_prob = likelihood
                final_msg = msg
                data = (final_prob, final_msg)
        final_msgs.append(data)
    score = 0
    broken_message = ""
    for likelihood, msg in final_msgs:
        if likelihood > score:
            score = likelihood
            final_msg = msg
    decoded_possible.append((score, final_msg))


while True:
    choice = input("Do you want to encode or decode? ").lower()

    if choice == "encode":
        cipher = input(
            "What type of cipher do you want to use?(Caesar,Atbash,Affine): "
        ).lower()

        if cipher == "help":
            print(
                """A Caesar cipher is a simple encryption technique where each letter in the plaintext is shifted a 
fixed number of positions down the alphabet.
For example, with a shift of 3:

A becomes D
B becomes E

An Atbash cipher is a substitution cipher where each letter of the alphabet is mapped to its reverse. For example:

A becomes Z
B becomes Y
C becomes X                                         
"""
            )

        message = input("Enter a message: ").lower()

        new_message = message.split()
        if cipher == "caesar":

            caesar_encode(new_message)
        elif cipher == "atbash":
            atbash_encode(new_message)
    else:
        message = input("Enter a message: ").lower()
        message = depunctuate(message)
        new_message = message.split()
        caesar_decode(new_message)
        atbash_decode(new_message)
        final_prob = 0
        decoded_message = ""
        for i, k in decoded_possible:
            if i > final_prob:
                final_prob = i
                decoded_message = k

        print(decoded_message if decoded_message else "Sorry, I didnt understand that.")
        if decoded_message:
            pyperclip.copy(decoded_message)
            print("Copied to clipboard")
        # print(decoded_possible)
