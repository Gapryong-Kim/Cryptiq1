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
    "w",
    "f",
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


def find_length_of_key(message):
    substrings = []
    ngram = 6
    mode_string = ""
    frequency = 1
    nospace = message.replace(" ", "")

    for i in range(len(nospace) - (ngram - 1)):

        substring = nospace[i : i + ngram]
        substrings.append(substring)
        if nospace.count(substring) > frequency:
            frequency = nospace.count(substring)
            mode_string = substring

    split = nospace.split(mode_string)
    indices = []
    start_index = 0
    for i in range(frequency):
        new_index = nospace.find(mode_string, start_index)
        indices.append(new_index)
        start_index = new_index + ngram

    lengths = []
    for index, i in enumerate(indices[:-1]):
        length = indices[index + 1] - indices[index]
        lengths.append(length)
    factors = []
    for i in lengths:
        for x in range(2, i):
            if i % x == 0:
                factors.append(x)
    common_factors = factors.copy()
    for factor in factors:
        for length in lengths:
            if length % factor != 0:
                common_factors.remove(factor)
                break
    common_factors = list(set(common_factors))
    lengths = sorted([i for i in common_factors])
    return lengths


def find_key(lengths, message):
    key_possibilities = []
    for length in lengths:
        message = message.replace(" ", "")
        common = ["e", "e", "a", "a", "a", "a", "a", "a"]
        key = ""
        columns = ["" for i in range(length)]
        for index, letter in enumerate(message):
            columns[index % length] += letter
        for column in columns:
            possibilities = []
            for shift in range(26):

                probability = 0
                decoded = ""
                for letter in column:
                    decoded += alphabet[(alphabet.index(letter) - shift) % 26]
                frequencies = []
                for i in alphabet:
                    frequencies.append((i, decoded.count(i)))
                frequencies = sorted(frequencies, key=lambda x: x[1], reverse=True)
                distribution = []
                for letter, num in frequencies:
                    distribution.append(letter)
                for letter in distribution:
                    cur_index = frequent_letters.index(letter)
                    if letter != "z" and letter != "e":

                        if distribution.index(letter) in [
                            cur_index,
                            cur_index + 1,
                            cur_index - 1,
                            cur_index - 2,
                            cur_index + 2,
                        ]:

                            probability += 1
                    elif letter == "e":
                        if distribution.index(letter) in [
                            cur_index,
                            cur_index + 1,
                        ]:
                            probability += 1
                    elif letter == "z":
                        if distribution.index(letter) in [
                            cur_index,
                            cur_index - 1,
                        ]:
                            probability += 1
                key_letter = alphabet[shift]
                data = (probability, key_letter)

                possibilities.append(data)
            max_prob = 0
            final_letter = ""
            for likelihood, letter in possibilities:
                if likelihood > max_prob:
                    max_prob = likelihood
                    final_letter = letter
            key += final_letter

        key_possibilities.append(key)
    return key_possibilities


def find_message(key_possibilities, message):
    message = message.replace(" ", "")
    decoded_possibilities = []
    for key in key_possibilities:
        decoded = ""
        current_key = key
        rendition = 0
        repeating_index = 0
        repeated_key = ""
        for i in range(len(message)):
            current_key += current_key[repeating_index]
            repeating_index += 1
        current_key = current_key[len(key) :]
        for ind, letter in enumerate(message):
            shift_index = alphabet.index(current_key[ind])
            new_index = (alphabet.index(letter) - shift_index) % 26
            new_letter = alphabet[new_index]
            decoded += new_letter
        distribution = sorted(
            [(decoded.count(i), i) for i in alphabet], key=lambda x: x[0], reverse=True
        )
        distribution = [i for k, i in distribution]
        probability = 0
        for letter in distribution:
            cur_index = frequent_letters.index(letter)
            if letter != "z" and letter != "e":

                if distribution.index(letter) in [
                    cur_index,
                    cur_index + 1,
                    cur_index - 1,
                    cur_index - 2,
                    cur_index + 2,
                ]:

                    probability += 1
            elif letter == "e":
                if distribution.index(letter) in [
                    cur_index,
                    cur_index + 1,
                ]:
                    probability += 1
            elif letter == "z":
                if distribution.index(letter) in [
                    cur_index,
                    cur_index - 1,
                ]:
                    probability += 1

        decoded_possibilities.append((probability, decoded, key))
    max_prob = 0
    final_msg = ""
    final_key = ""
    for likelihood, message, key in decoded_possibilities:
        if likelihood > max_prob:
            max_prob = likelihood
            final_msg = message
            final_key = key
    return (max_prob, final_key, final_msg)


message = depunctuate(input("Enter message: ").lower())
possible = []
possible.append(
    find_message((find_key((find_length_of_key(message)), message)), message)
)
possible.append(
    find_message(
        (find_key((find_length_of_key(message[::-1])), message[::-1])), message[::-1]
    )
)
possible.sort(key=lambda x: x[0], reverse=True)
key = possible[0][1]
final_msg = possible[0][2]
print(f"key: {key}")
print(final_msg)
