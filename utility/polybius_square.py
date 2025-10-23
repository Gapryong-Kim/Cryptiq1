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


def polybius_standardize(message):
    message = message.replace(" ", "")
    coords = []
    coord = ""
    for i, k in enumerate(message):
        if i % 2 == 0 and coord:
            coords.append(coord)
            coord = ""
        coord += k
    if coord:
        coords.append(coord)
    unique_coords = list(set(coords))
    standardized = ""
    for i in coords:
        standardized += alphabet[unique_coords.index(i)]
    return standardized.upper()


