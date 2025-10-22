def simple_ct(message):
    message = message.replace(" ", "")
    length = 5
    while len(message) % length != 0:
        message += "%"
    blocks = []
    current_block = ""
    for i, k in enumerate(message):
        print(current_block)
        if len(current_block) != length:
            current_block += k
        if len(current_block) == length:
            blocks.append(current_block)
            current_block = ""

    decoded = ""
    for i in list(zip(*blocks)):
        for x in i:
            decoded += x
    decoded = decoded.replace("%", "")
    print(decoded)


simple_ct(input("Enter message: "))
print(*zip(*["abcde", "abcde"]))
