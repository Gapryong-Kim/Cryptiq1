# playfair_breaker.py
import random, math, re, os, json
from typing import Dict, Tuple, Callable, Optional

AZ25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J merged to I


def norm(s: str) -> str:
    return re.sub(r"[^A-Za-z]", "", s).upper().replace("J", "I")


# -----------------------
# Tetragram scoring model
# -----------------------

def load_tetragrams_txt(path: str) -> Tuple[Dict[str, float], float]:
    """
    File format: lines like
      TION 123456
      THER 234567
    Returns dict tetragram->log10(prob), and floor for unseen.
    """
    counts: Dict[str, int] = {}
    total = 0

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().upper()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2:
                continue
            tg, c = parts[0], parts[1]
            if len(tg) != 4 or not tg.isalpha():
                continue
            try:
                ci = int(c)
            except ValueError:
                continue
            counts[tg] = counts.get(tg, 0) + ci
            total += ci

    if total <= 0 or not counts:
        raise ValueError("Tetragram TXT model appears empty/invalid.")

    logp = {tg: math.log10(c / total) for tg, c in counts.items()}
    floor = math.log10(0.01 / total)  # mild unseen penalty
    return logp, floor


def load_tetragrams_json(path: str) -> Tuple[Dict[str, float], float]:
    """
    JSON format expected:
      {"logp": {"TION": -2.2, ...}, "floor": -7.7}
    """
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)

    if not isinstance(obj, dict) or "logp" not in obj:
        raise ValueError("tetragrams.json missing required key 'logp'.")

    logp = obj["logp"]
    floor = obj.get("floor", None)

    if not isinstance(logp, dict) or not logp:
        raise ValueError("tetragrams.json 'logp' is empty/invalid.")

    # floor can be absent; compute a reasonable default from min logp
    if floor is None:
        try:
            floor = min(float(v) for v in logp.values()) - 2.0
        except Exception:
            floor = -8.0

    # ensure values are floats
    logp2: Dict[str, float] = {}
    for k, v in logp.items():
        if isinstance(k, str) and len(k) == 4 and k.isalpha():
            try:
                logp2[k.upper()] = float(v)
            except Exception:
                pass

    if not logp2:
        raise ValueError("tetragrams.json contains no usable tetragrams.")

    return logp2, float(floor)


# fallback (only if no model files found) — weaker
T4_FALLBACK = {
    "TION": -2.2, "THER": -2.3, "WITH": -2.6, "HERE": -2.7, "MENT": -2.8, "THAT": -2.9, "IONS": -3.0,
    "THIS": -3.0, "ATIO": -3.1, "EVER": -3.2, "FROM": -3.2, "OUGH": -3.3, "IGHT": -3.3, "HAVE": -3.4,
    "OULD": -3.4, "THEM": -3.4, "THEN": -3.5, "WERE": -3.5, "INTH": -3.6, "ERES": -3.7, "SION": -3.7,
    "OUND": -3.7, "EDTH": -3.8, "ANDT": -3.8, "NGTH": -3.8, "OFTH": -3.9, "DTHE": -3.9, "THEI": -3.9
}
FLOOR_FALLBACK = -6.5


def make_score_fn(
    json_path: str = "tetragrams.json",
    txt_path: str = "english_tetragrams.txt",
) -> Tuple[Callable[[str], float], str]:
    """
    Returns (score_fn, model_source_string)
    model_source_string is one of: "json", "txt", "fallback"
    """

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Candidate JSON paths (add /mnt/data explicitly)
    json_candidates = [
        "/mnt/data/tetragrams.json",
        json_path if os.path.isabs(json_path) else os.path.join(base_dir, json_path),
        os.path.join(base_dir, "tetragrams.json"),
    ]

    for jp in json_candidates:
        if jp and os.path.exists(jp):
            logp, floor = load_tetragrams_json(jp)

            def s(text: str) -> float:
                text = re.sub(r"[^A-Z]", "", text.upper()).replace("J", "I")
                return sum(logp.get(text[i:i + 4], floor) for i in range(len(text) - 3))

            return s, "json"

    # Candidate TXT paths
    txt_candidates = [
        txt_path if os.path.isabs(txt_path) else os.path.join(base_dir, txt_path),
        os.path.join(base_dir, "english_tetragrams.txt"),
    ]

    for tp in txt_candidates:
        if tp and os.path.exists(tp):
            logp, floor = load_tetragrams_txt(tp)

            def s(text: str) -> float:
                text = re.sub(r"[^A-Z]", "", text.upper()).replace("J", "I")
                return sum(logp.get(text[i:i + 4], floor) for i in range(len(text) - 3))

            return s, "txt"

    # Fallback
    def s(text: str) -> float:
        text = re.sub(r"[^A-Z]", "", text.upper()).replace("J", "I")
        return sum(T4_FALLBACK.get(text[i:i + 4], FLOOR_FALLBACK) for i in range(len(text) - 3))

    return s, "fallback"


# -----------------------
# Playfair decrypt
# -----------------------

def decrypt(square: str, ct: str) -> str:
    # pos arrays for A-Z (J treated as I before calling)
    posr = [0] * 26
    posc = [0] * 26
    for i, ch in enumerate(square):
        k = ord(ch) - 65
        posr[k], posc[k] = divmod(i, 5)

    out = []
    for i in range(0, len(ct), 2):
        a = ord(ct[i]) - 65
        b = ord(ct[i + 1]) - 65
        ra, ca = posr[a], posc[a]
        rb, cb = posr[b], posc[b]

        if ra == rb:  # same row -> left
            out.append(square[ra * 5 + (ca - 1) % 5])
            out.append(square[rb * 5 + (cb - 1) % 5])
        elif ca == cb:  # same col -> up
            out.append(square[((ra - 1) % 5) * 5 + ca])
            out.append(square[((rb - 1) % 5) * 5 + cb])
        else:  # rectangle
            out.append(square[ra * 5 + cb])
            out.append(square[rb * 5 + ca])

    return "".join(out)


# -----------------------
# Key mutations
# -----------------------

def swap_two(sq: str) -> str:
    s = list(sq)
    i, j = random.sample(range(25), 2)
    s[i], s[j] = s[j], s[i]
    return "".join(s)


def swap_rows(sq: str) -> str:
    s = list(sq)
    r1, r2 = random.sample(range(5), 2)
    for c in range(5):
        i1, i2 = r1 * 5 + c, r2 * 5 + c
        s[i1], s[i2] = s[i2], s[i1]
    return "".join(s)


def swap_cols(sq: str) -> str:
    s = list(sq)
    c1, c2 = random.sample(range(5), 2)
    for r in range(5):
        i1, i2 = r * 5 + c1, r * 5 + c2
        s[i1], s[i2] = s[i2], s[i1]
    return "".join(s)


def rotate_square(sq: str) -> str:
    g = [list(sq[r * 5:(r + 1) * 5]) for r in range(5)]
    rot = list(zip(*g[::-1]))
    return "".join("".join(row) for row in rot)


def reverse_row(sq: str) -> str:
    s = list(sq)
    r = random.randrange(5)
    s[r * 5:r * 5 + 5] = s[r * 5:r * 5 + 5][::-1]
    return "".join(s)


def reverse_col(sq: str) -> str:
    s = list(sq)
    c = random.randrange(5)
    col = [s[r * 5 + c] for r in range(5)][::-1]
    for r in range(5):
        s[r * 5 + c] = col[r]
    return "".join(s)


def mutate(sq: str) -> str:
    # bias toward small moves, occasionally big
    t = random.random()
    if t < 0.70:
        return swap_two(sq)
    elif t < 0.88:
        return random.choice([swap_rows, swap_cols])(sq)
    else:
        return random.choice([reverse_row, reverse_col, rotate_square])(sq)


# -----------------------
# Annealing
# -----------------------

def anneal(ct: str, score_fn, restarts: int, steps: int, temp: float, cool: float, start_sq: Optional[str] = None):
    best_sq, best_sc, best_pt = None, -1e99, ""

    for r in range(restarts):
        if start_sq is not None and r == 0:
            cur_sq = start_sq
        else:
            sq_list = list(AZ25)
            random.shuffle(sq_list)
            cur_sq = "".join(sq_list)

        cur_pt = decrypt(cur_sq, ct)
        cur_sc = score_fn(cur_pt)

        local_best_sq, local_best_sc, local_best_pt = cur_sq, cur_sc, cur_pt

        T = temp
        for _ in range(steps):
            cand_sq = mutate(cur_sq)
            cand_pt = decrypt(cand_sq, ct)
            cand_sc = score_fn(cand_pt)
            d = cand_sc - cur_sc

            if d >= 0 or random.random() < math.exp(d / max(T, 1e-9)):
                cur_sq, cur_sc = cand_sq, cand_sc
                if cur_sc > local_best_sc:
                    local_best_sq, local_best_sc, local_best_pt = cur_sq, cur_sc, cand_pt

            T *= cool

        if local_best_sc > best_sc:
            best_sq, best_sc, best_pt = local_best_sq, local_best_sc, local_best_pt

    return best_sq, best_sc, best_pt


def crack_playfair(ciphertext: str, time_budget: str = "normal", seed: Optional[int] = None):
    if seed is not None:
        random.seed(seed)

    ct = norm(ciphertext)
    if len(ct) % 2:
        ct += "X"

    score_fn, model_src = make_score_fn("tetragrams.json", "english_tetragrams.txt")

    if time_budget == "fast":
        p1 = dict(restarts=18, steps=1800, temp=7.0, cool=0.9990)
        refine_loops, refine_steps = 8, 4500
        refine_temp, refine_cool = 5.5, 0.99935
    elif time_budget == "hard":
        p1 = dict(restarts=40, steps=3200, temp=7.2, cool=0.9991)
        refine_loops, refine_steps = 20, 8000
        refine_temp, refine_cool = 5.6, 0.99935
    else:
        p1 = dict(restarts=25, steps=2500, temp=7.0, cool=0.9990)
        refine_loops, refine_steps = 15, 6000
        refine_temp, refine_cool = 5.5, 0.99935

    sq1, sc1, pt1 = anneal(ct, score_fn, **p1)
    best_sq, best_sc, best_pt = sq1, sc1, pt1

    def nearby_start(base: str) -> str:
        sq = base
        for _ in range(40):
            sq = swap_two(sq)
        return sq

    for _ in range(refine_loops):
        start_sq = nearby_start(best_sq)
        sq2, sc2, pt2 = anneal(
            ct, score_fn,
            restarts=1,
            steps=refine_steps,
            temp=refine_temp,
            cool=refine_cool,
            start_sq=start_sq
        )
        if sc2 > best_sc:
            best_sq, best_sc, best_pt = sq2, sc2, pt2

    return best_sq, best_sc, best_pt, model_src


def pretty_square(sq: str) -> str:
    return "\n".join(" ".join(sq[r * 5:(r + 1) * 5]) for r in range(5))


if __name__ == "__main__":
    CIPHERTEXT = input("enter ciphertext: ").strip()

    sq, sc, pt, model_src = crack_playfair(
        CIPHERTEXT,
        time_budget="normal",   # "fast" | "normal" | "hard"
        seed=42
    )

    print("Model used:", model_src)  # "json" if tetragrams.json is found
    print("\nBEST SQUARE:\n" + pretty_square(sq))
    print("\nSCORE:", sc)
    print("\nPLAINTEXT:\n" + pt)
    print("\nTip: If plaintext is close-but-messy, remove filler X/Q and re-space.")
