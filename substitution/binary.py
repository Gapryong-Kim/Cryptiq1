binary = input("Enter binary pattern: ")
binary = binary.replace(" ", "")
while binary:

    number = 0
    for i, k in enumerate(binary):
        if k == "1":
            denary = 2 ** (len(binary) - i - 1)
            number += denary

    print(number)
    binary = input("Enter binary pattern: ")
