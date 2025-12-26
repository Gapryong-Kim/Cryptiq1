common_words = [
    "the","be","to","of","and","a","in","that","have","i","it","for","not","on","with","he","as","you","do","at",
    "this","but","his","by","from","they","we","say","her","she","or","an","will","my","one","all","would","there",
    "their","what","so","up","out","if","about","who","get","which","go","me","when","make","can","like","no","just",
    "him","know","take","into","your","good","some","could","them","see","other","than","then","now","look","only",
    "come","its","over","think","also","back","after","use","two","how","our","work","first","well","way","even",
    "new","want","because","any","these","give","day","most","us",
]



def railfence_decode(cipher, rails=3, offset=0):
    if rails <= 1 or rails >= len(cipher):
        return cipher

    n = len(cipher)
    cycle = 2 * rails - 2
    offset = int(offset) % cycle if cycle else 0

    # Step 1: build the zig-zag pattern (row index for each char)
    pattern = []
    row = 0
    direction = 1

    # advance zig-zag by offset (no chars placed yet)
    for _ in range(offset):
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    for _ in range(n):
        pattern.append(row)

        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    # Step 2: determine how many characters go in each rail
    rail_counts = [0] * rails
    for r in pattern:
        rail_counts[r] += 1

    # Step 3: split ciphertext into rails
    rails_content = []
    idx = 0
    for count in rail_counts:
        rails_content.append(list(cipher[idx:idx + count]))
        idx += count

    # Step 4: rebuild plaintext following the pattern
    rail_pos = [0] * rails
    result = []

    for r in pattern:
        result.append(rails_content[r][rail_pos[r]])
        rail_pos[r] += 1

    return ''.join(result)


def _score_english(s: str) -> int:
    """Very light score: sum of occurrences of common words."""
    s = s.lower()
    return sum(s.count(w) for w in common_words)

def railfence_break(message: str):
   current_probability=0

   current_decode=''
   current_key=''
   for rails in range(30):
       for offset in range(30):
           decoded=railfence_decode(message,rails,offset)
           if _score_english(decoded)>current_probability:
               current_probability=_score_english(decoded)
               current_decode=decoded
               current_key=f'rails: {rails} offset: {offset}'
   return current_key,current_decode



           
