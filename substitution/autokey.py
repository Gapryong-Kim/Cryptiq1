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
message = input("Enter a message: ").lower().replace(" ", "")
known_plaintext = "the"
key = ""
for i, k in enumerate(message[: len(known_plaintext)]):
    plain_index = alphabet.index(known_plaintext[i])
    cipher_index = alphabet.index(k)
    new_index = (cipher_index - plain_index + 26) % 26
    key += alphabet[new_index]
print(key)
