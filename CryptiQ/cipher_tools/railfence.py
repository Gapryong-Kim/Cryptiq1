common_words = [
    "the","be","to","of","and","a","in","that","have","i","it","for","not","on","with","he","as","you","do","at",
    "this","but","his","by","from","they","we","say","her","she","or","an","will","my","one","all","would","there",
    "their","what","so","up","out","if","about","who","get","which","go","me","when","make","can","like","no","just",
    "him","know","take","into","your","good","some","could","them","see","other","than","then","now","look","only",
    "come","its","over","think","also","back","after","use","two","how","our","work","first","well","way","even",
    "new","want","because","any","these","give","day","most","us",
]

def _railfence_decrypt(ct_letters: str, rails: int) -> str:
    """Decrypt letters-only rail-fence with a known rail count."""
    n = len(ct_letters)
    if rails <= 1 or rails >= n:
        return ct_letters

    # Build the zig-zag pattern of row indices for positions 0..n-1
    pattern = []
    row = 0
    direction = 1  # 1 = down, -1 = up
    for _ in range(n):
        pattern.append(row)
        row += direction
        if row == rails - 1 or row == 0:
            direction *= -1

    # Count how many chars go to each row
    row_counts = [0] * rails
    for r in pattern:
        row_counts[r] += 1

    # Slice ciphertext into rows according to the counts
    rows = []
    idx = 0
    for count in row_counts:
        rows.append(list(ct_letters[idx:idx + count]))
        idx += count

    # Read off rows following the same zig-zag
    row_ptrs = [0] * rails
    out_chars = []
    for r in pattern:
        out_chars.append(rows[r][row_ptrs[r]])
        row_ptrs[r] += 1

    return "".join(out_chars)

def _score_english(s: str) -> int:
    """Very light score: sum of occurrences of common words."""
    s = s.lower()
    return sum(s.count(w) for w in common_words)

def railfence_break(message: str):
    """
    Auto-detect rails (2..min(10, len_letters)) and return (key, restored_plaintext)
    Restores the original spacing/punctuation and case from 'message'.
    """
    # Extract letters only (preserve for reinsertion later)
    letters_only = [ch for ch in message if ch.isalpha()]
    n_letters = len(letters_only)
    if n_letters == 0:
        return "2 rails", message  # nothing to do

    ct_letters = "".join(ch.lower() for ch in letters_only)

    best = None  # tuple(score, plaintext_letters, rails)
    max_rails = max(2, min(20, n_letters))  # don’t try more rails than letters

    for rails in range(2, max_rails + 1):
        pt_letters = _railfence_decrypt(ct_letters, rails)
        score = _score_english(pt_letters)
        cand = (score, pt_letters, rails)
        if best is None or cand > best:
            best = cand

    _, best_letters, best_rails = best

    # Re-insert non-letters and preserve original case
    restored = []
    li = 0
    for ch in message:
        if ch.isalpha():
            dec_ch = best_letters[li]
            restored.append(dec_ch.upper() if ch.isupper() else dec_ch)
            li += 1
        else:
            restored.append(ch)

    return f"{best_rails} rails", "".join(restored)
