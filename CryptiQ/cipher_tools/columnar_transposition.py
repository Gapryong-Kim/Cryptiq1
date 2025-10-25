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
    "is",
    "are",
    "was",
    "were",
    "been",
    "has",
    "more",
    "many",
    "those",
    "who",
    "may",
    "might",
    "shall",
    "do",
    "did",
    "make",
    "made",
    "see",
    "seen",
    "get",
    "got",
    "had",
    "much",
    "very",
]


def columnar_break(message):
    final_possibilities = []
    original_message = message
    message=''.join(i for i in message if i.isalpha()).lower()
    message = message.replace(" ", "")
    preserved_message = message
    for key_length in range(1, 9):
        print(key_length)
        message = preserved_message
        while len(message) % key_length != 0:
            message += "%"
        rows = []
        row = ""
        for index, i in enumerate(message):
            row += i
            if (index + 1) % (len(message) / key_length) == 0:
                rows.append(row)
                row = ""
        perms = list(permutations(range(key_length)))
        possibilities = []
        for perm in perms:
            config = []
            for index in perm:
                config.append(rows[index])
            decoded = list(zip(*config))
            true_decoded = ""
            for i in decoded:
                for letter in i:
                    true_decoded += letter
            true_decoded = true_decoded.replace("%", "")
            probability = sum(true_decoded.count(i) for i in common_words)
            possibilities.append((probability, true_decoded,perm))
        possibilities.sort(key=lambda x: x[0], reverse=True)

        final_possibilities.append(possibilities[0])
    final_possibilities.sort(key=lambda x: x[0], reverse=True)
    final_key=final_possibilities[0][2]
    final_msg= final_possibilities[0][1]
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


