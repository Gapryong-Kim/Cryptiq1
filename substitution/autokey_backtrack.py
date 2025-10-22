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

message = input("Enter a message: ").replace(" ", "")[::-1].lower()
known_plaintext = "kaiser"
decoded = ""
while message:
    plaintext_portion = ""
    for index, letter in enumerate(message[: len(known_plaintext)]):
        plain_index = alphabet.index(known_plaintext[index])
        cipher_index = alphabet.index(letter)
        new_index = (cipher_index - plain_index) % 26
        plaintext_portion += alphabet[new_index]
    print(plaintext_portion)
    decoded += plaintext_portion
    if len(message) != len(known_plaintext):
        message = message[len(known_plaintext) :]
    else:
        message = ""

message = message[::-1]
message += "kaiser"
print(message)
