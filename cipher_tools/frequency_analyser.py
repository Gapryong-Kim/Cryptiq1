normal_distribution = [
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


def analyse(message):
    message=''.join(i for i in message if i.isalpha()).lower()
    frequency_distribution = []
    letter_distribution = []
    ngrams=[]
    message = message.replace(" ", "")
    letter_commonality = []
    for i in normal_distribution:
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
        ngrams.append(substrings[:10])
        ngram -= 1

    




    for i in normal_distribution:
        frequency_distribution.append((i, message.count(i)))
    frequency_distribution.sort(key=lambda x: x[1], reverse=True)
    for i in frequency_distribution:
        letter_distribution.append(i[0])
    distribution_score = 0
    for index, letter in enumerate(letter_distribution):
        normal_index = normal_distribution.index(letter)

        if letter not in ["e", "z"]:
            if index in [normal_index, normal_index + 1, normal_index - 1]:
                distribution_score += 1
        else:
            if letter == "e":
                if index in [normal_index, normal_index + 1]:
                    distribution_score += 1
            elif letter == "z":
                if index in [normal_index, normal_index - 1]:
                    distribution_score += 1
    if distribution_score >= 10:
        type="Transposition (Block Transposition, Columnar transposition etc.)"
    else:
        type="Substitution (Caesar, Vigenère Cipher etc.)"
    trigrams=ngrams[0]
    bigrams=ngrams[1]

    return trigrams,bigrams,frequency_distribution,type

