roman_numerals = ["i", "v", "x", "l", "c", "d", "m"]
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

message = input("Enter a message: ").lower()
for i in range(26):
    decoded = ""
    for k in message:
        new_index = (alphabet.index(k) + i) % 26
        decoded += alphabet[new_index]
    print(i, decoded.upper())
