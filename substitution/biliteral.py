bialphabet = {
    "AAAAA": "A",
    "AAAAB": "B",
    "AAABA": "C",
    "AAABB": "D",
    "AABAA": "E",
    "AABAB": "F",
    "AABBA": "G",
    "AABBB": "H",
    "ABAAA": "I",
    "ABAAB": "K",
    "ABABA": "L",
    "ABABB": "M",
    "ABBAA": "N",
    "ABBAB": "O",
    "ABBBA": "P",
    "ABBBB": "Q",
    "BAAAA": "R",
    "BAAAB": "S",
    "BAABA": "T",
    "BAABB": "U",
    "BABAA": "W",
    "BABAB": "X",
    "BABBA": "Y",
    "BABBB": "Z",
}


def biliteral_decode(message):
    message = message.replace(" ", "")
    blocks = []
    coord = ""
    for i, k in enumerate(message):
        if i % 5 == 0 and coord:
            blocks.append(coord)
            coord = ""
        coord += k
    print(blocks)
    decoded = ""
    for i in blocks:
        decoded += bialphabet[i]
    print(decoded)


message = input("Enter message: ").upper()
biliteral_decode(message)
