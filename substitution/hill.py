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


def find_matrix(ciphertext, plaintext):
    plain_indices = []
    c = []
    for i in plaintext[:2]:
        c.append(alphabet.index(i))
    plain_indices.append(c)
    c = []
    for i in plaintext[2:]:
        c.append(alphabet.index(i))
    plain_indices.append(c)
    print(plain_indices)

    cipher_indices = []
    c = []
    for i in ciphertext[:2]:
        c.append(alphabet.index(i))
    cipher_indices.append(c)
    c = []
    for i in ciphertext[2:]:
        c.append(alphabet.index(i))
    cipher_indices.append(c)
    print(cipher_indices)


find_matrix(input("Enter ciphertext: "), input("Enter known plaintext: "))
