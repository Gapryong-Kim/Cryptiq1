import pyperclip

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


def railfence_break(message):
    decoded_possible = []
    original_message = message
    message=''.join(i for i in message if i.isalpha() ).lower()

    for rails in range(2, 10):

        message = message.replace(" ", "")
        cycle_length = 2 * (rails - 1)
        full_cycles = len(message) // cycle_length
        extra_cycle = round(
            (((len(message) / cycle_length) - full_cycles) * cycle_length)
        )
        row_lengths = []
        for i in range(rails):
            if i == 0 or i == rails - 1:
                row_lengths.append(full_cycles)
            else:
                row_lengths.append(full_cycles * 2)

        true_row_lengths = []
        for i in row_lengths:
            if extra_cycle > 0:
                i += 1
                extra_cycle -= 1
            true_row_lengths.append(i)
        truest_row_lengths = []

        true_row_lengths = true_row_lengths[::-1]
        for index, i in enumerate(true_row_lengths):
            if extra_cycle > 0:
                if index != 0:
                    i += 1
                    extra_cycle -= 1
            truest_row_lengths.append(i)
        truest_row_lengths = truest_row_lengths[::-1]
        rows = ["" for i in range(rails)]
        previous_length = 0
        for index, i in enumerate(truest_row_lengths):
            rows[index] += message[previous_length : previous_length + i]
            previous_length += i
        row_index = 0
        word_index = 0
        direction = -1
        true_decoded = []
        word_indices = [0] * rails 
        decoded = ""
        for i in range(len(message)):
            decoded += rows[row_index][word_indices[row_index]]
            if row_index == 0 or row_index == rails - 1:
                direction *= -1
            word_indices[row_index] += 1
            row_index += direction
        probability = sum(decoded.count(i) for i in common_words)
        decoded_possible.append((probability, decoded,rails))
    decoded_possible.sort(key=lambda x: x[0], reverse=True)
    final_msg=decoded_possible[0][1]
    final_key=f'{decoded_possible[0][2]} rails'
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


