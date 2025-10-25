from itertools import permutations

common_words = list(
    set(
        [
            "the",
            "be",
            "to",
            "of",
            "and",
            "a",
            "in",
            "that",
            "have",
            "i",
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
    )
)


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


def permutation_break(message):
    original_message = message
    message=''.join(i for i in message if i.isalpha()).lower()
    messages = []
    for length in range(1, 8):
        message = message.replace(" ", "")
        perms = list(set(permutations(range(1, length + 1))))
        block = ""
        blocks = []
        for index, letter in enumerate(message):
            block += letter
            if (index + 1) % length == 0:
                blocks.append(block)
                block = ""
        if block:
            blocks.append(block)
        possibilities = []
        for perm in perms:
            decoded = ""
            for block in blocks:
                for index in perm:
                    if index - 1 < len(block):
                        decoded += block[index - 1]
            possibilities.append((perm, decoded))
        final_possibilities = []
        for k, i in possibilities:
            probability = 0
            for word in common_words:
                probability += i.count(word)
            final_possibilities.append((probability, k, i))
        final_possibilities.sort(key=lambda x: x[0], reverse=True)
        final_prob = final_possibilities[0][0]
        final_key = final_possibilities[0][1]
        final_msg = final_possibilities[0][2]

        messages.append((final_prob, final_key, final_msg))
    messages.sort(key=lambda x: x[0], reverse=True)
    final_msg=messages[0][2]
    final_key=messages[0][1]
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

    return final_key, restored_text



