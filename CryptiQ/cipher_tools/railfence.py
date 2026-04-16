# English bigram frequencies (per 100 bigrams, approximated from large corpora).
# This is the standard scoring method for transposition ciphers — letter
# frequency is useless because rearranging chars never changes it.
BIGRAMS = {
    'th':3.56,'he':3.07,'in':2.43,'er':2.05,'an':1.99,'re':1.85,
    'on':1.76,'en':1.75,'at':1.49,'es':1.46,'ed':1.44,'te':1.44,
    'ti':1.39,'or':1.28,'st':1.25,'ar':1.20,'nd':1.18,'to':1.17,
    'nt':1.16,'is':1.13,'ou':1.11,'ea':1.10,'ng':1.05,'as':1.03,
    'it':1.00,'ha':1.00,'se':0.98,'et':0.95,'hi':0.93,'of':0.94,
    'de':0.89,'le':0.88,'sa':0.87,'ve':0.87,'al':0.87,'ri':0.83,
    'ro':0.80,'ic':0.79,'ne':0.78,'ta':0.78,'io':0.77,'la':0.76,
    'el':0.75,'me':0.74,'ec':0.71,'li':0.70,'il':0.70,'ch':0.68,
    'om':0.67,'ur':0.66,'tr':0.65,'fo':0.65,'no':0.65,'ly':0.64,
    'co':0.63,'ra':0.62,'ac':0.62,'ma':0.61,'ot':0.60,'di':0.59,
    'ho':0.58,'we':0.57,'be':0.57,'ce':0.55,'wi':0.55,'ge':0.55,
    'ts':0.55,'ad':0.54,'pe':0.54,'ai':0.52,'gh':0.51,'wa':0.51,
    'ss':0.51,'sh':0.51,'wh':0.50,'ni':0.49,'ca':0.49,'ie':0.48,
    'rs':0.47,'ow':0.47,'ll':0.46,'pr':0.46,'mo':0.45,'oo':0.44,
    'lo':0.43,'un':0.43,'us':0.42,'mi':0.42,'ab':0.41,'pa':0.41,
    'ns':0.41,'am':0.40,'po':0.40,'so':0.40,'ut':0.40,'do':0.39,
    'na':0.38,'pl':0.38,'fi':0.37,'id':0.36,'bl':0.36,'cl':0.35,
    'fr':0.35,'ef':0.34,'rd':0.34,'ba':0.34,'fe':0.33,'pi':0.33,
    'bu':0.33,'pu':0.33,'eg':0.32,'im':0.32,'su':0.32,'os':0.32,
    'ew':0.31,'em':0.31,'da':0.31,
}


def _score_english(text: str) -> float:
    """
    Score text by summing bigram frequencies over its alpha characters only.

    WHY BIGRAMS, NOT WORD COUNTS OR LETTER FREQ:
    - Rail fence is a *transposition* cipher — it only rearranges characters,
      so single-letter frequencies are identical in every candidate decode.
      Chi-squared and letter-frequency scoring give the same score to all of them.
    - Word-count scoring fails here because digits/capitals in the ciphertext
      break word boundaries mid-word in most wrong decodes.
    - Bigrams over alpha-only chars are immune to both problems: adjacent letter
      pairs change dramatically between a scrambled and a correct decode.
    """
    letters = ''.join(c.lower() for c in text if c.isalpha())
    if len(letters) < 2:
        return 0.0
    return sum(BIGRAMS.get(letters[i:i+2], 0.01)
               for i in range(len(letters) - 1))


def railfence_decode(cipher: str, rails: int = 3, offset: int = 0) -> str:
    if rails <= 1 or rails >= len(cipher):
        return cipher
    n = len(cipher)
    cycle = 2 * rails - 2
    offset = int(offset) % cycle if cycle else 0

    pattern, row, direction = [], 0, 1
    for _ in range(offset):
        if   row == 0:          direction = 1
        elif row == rails - 1: direction = -1
        row += direction
    for _ in range(n):
        pattern.append(row)
        if   row == 0:          direction = 1
        elif row == rails - 1: direction = -1
        row += direction

    rail_counts = [0] * rails
    for r in pattern:
        rail_counts[r] += 1

    rails_content, idx = [], 0
    for count in rail_counts:
        rails_content.append(list(cipher[idx : idx + count]))
        idx += count

    rail_pos = [0] * rails
    result = []
    for r in pattern:
        result.append(rails_content[r][rail_pos[r]])
        rail_pos[r] += 1
    return ''.join(result)


def railfence_break(message: str, max_rails: int = 30) -> tuple[str, str]:
    """
    Brute-force the rail-fence key using bigram scoring.
    Returns (key_string, decoded_text) for the best candidate.
    Also prints the top 5 so you can sanity-check near-misses.
    """
    candidates = []
    for rails in range(2, min(max_rails + 1, len(message))):
        cycle = 2 * rails - 2
        for offset in range(cycle):  # exactly one full period — no redundancy
            decoded = railfence_decode(message, rails, offset)
            candidates.append((_score_english(decoded), rails, offset, decoded))

    candidates.sort(reverse=True)

    print("Top 5 candidates:")
    for score, r, o, text in candidates[:5]:
        print(f"  score={score:.1f}  rails={r}  offset={o}  →  {text[:60]}...")

    score, r, o, best = candidates[0]
    return f"rails={r}  offset={o}", best
