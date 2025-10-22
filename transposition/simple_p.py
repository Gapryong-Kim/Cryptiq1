def reverse(message):
    message = message.replace(" ", "")
    blocks = []
    coord = ""
    length = 5
    for i, k in enumerate(message):
        if i % length == 0:
            blocks.append(coord)
            coord = ""
        coord += k
    blocks = blocks[1:]

    reverse = ""
    for i in blocks:
        reverse += i[::-1]
    print(reverse)


reverse(input("Enter message: "))
