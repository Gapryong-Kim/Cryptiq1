common_words = [
    "the",
    "be",
    "to",
    "of",
    "and",
    "in",
    "that",
    "have",
    "it",
    "for",
    "not",
    "with",
    "he",
    "as",
    "you",
    "do",
    "at",
    "this",
    "but",
    "his",
    "from",
    "they",
    "say",
    "her",
    "she",
    "will",
    "one",
    "all",
    "would",
    "there",
    "their",
    "what",
    "about",
    "who",
    "get",
    "which",
    "when",
    "make",
    "can",
    "like",
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



def vigenere_break(message):
    original_message = message
    # Keep only letters for analysis
    cleaned_message = ''.join(i for i in message if i.isalpha()).lower()
    messages = (cleaned_message, cleaned_message[::-1])
    possible = []
    
    for msg in messages:
        lengths = range(5, 10)
        key_possibilities = []
        for length in lengths:
            msg = msg.replace(" ", "")
            key = ""
            columns = ["" for _ in range(length)]
            for index, letter in enumerate(msg):
                columns[index % length] += letter

            for column in columns:
                possibilities = []
                for shift in range(26):
                    probability = 0
                    decoded = ""
                    for letter in column:
                        decoded += alphabet[(alphabet.index(letter) - shift) % 26]
                    frequencies = [(i, decoded.count(i)) for i in alphabet]
                    frequencies = sorted(frequencies, key=lambda x: x[1], reverse=True)
                    distribution = [letter for letter, _ in frequencies]

                    for letter in distribution:
                        if letter != "z" and letter != "e":
                            if distribution.index(letter) in [
                                frequent_letters.index(letter),
                                frequent_letters.index(letter) + 1,
                                frequent_letters.index(letter) - 1,
                                frequent_letters.index(letter) - 2,
                                frequent_letters.index(letter) + 2,
                            ]:
                                probability += 1
                        elif letter == "e":
                            if distribution.index(letter) in [
                                frequent_letters.index(letter),
                                frequent_letters.index(letter) + 1,
                            ]:
                                probability += 1
                        elif letter == "z":
                            if distribution.index(letter) in [
                                frequent_letters.index(letter),
                                frequent_letters.index(letter) - 1,
                            ]:
                                probability += 1
                    key_letter = alphabet[shift]
                    possibilities.append((probability, key_letter))

                max_prob = 0
                final_letter = ""
                for likelihood, letter in possibilities:
                    if likelihood > max_prob:
                        max_prob = likelihood
                        final_letter = letter
                key += final_letter

            key_possibilities.append(key)

        msg = msg.replace(" ", "")
        decoded_possibilities = []
        for key in key_possibilities:
            decoded = ""
            current_key = key
            repeating_index = 0
            for i in range(len(msg)):
                current_key += current_key[repeating_index]
                repeating_index += 1
            current_key = current_key[len(key):]
            for ind, letter in enumerate(msg):
                shift_index = alphabet.index(current_key[ind])
                new_index = (alphabet.index(letter) - shift_index) % 26
                new_letter = alphabet[new_index]
                decoded += new_letter

            for i in decoded:
                probability = sum(decoded.count(i) for i in common_words)
            decoded_possibilities.append((probability, decoded, key))

        max_prob = 0
        final_msg = ""
        final_key = ""
        for likelihood, msg_decoded, key in decoded_possibilities:
            if likelihood > max_prob:
                max_prob = likelihood
                final_msg = msg_decoded
                final_key = key

        possible.append((max_prob, final_key, final_msg))

    possible.sort(key=lambda x: x[0], reverse=True)
    key = possible[0][1]
    final_msg = possible[0][2]

    # === Reinsert punctuation & spaces ===
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

    return key, restored_text

