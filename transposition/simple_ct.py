def simple_ct(message, length):
    message = message.replace(" ", "")

    while len(message) % length != 0:
        message += "%"
    blocks = []
    coord = ""

    for i, k in enumerate(message):
        if i % length == 0:
            blocks.append(coord)
            coord = ""
        coord += k
    blocks = blocks[1:]
    print(blocks)
    columnone = ""
    for i in blocks:
        columnone += i[0]
    columntwo = ""
    for i in blocks:
        columntwo += i[1]
    columnthree = ""
    for i in blocks:
        columnthree += i[2]
    columnfour = ""
    for i in blocks:
        columnfour += i[3]
    columnfive = ""
    for i in blocks:
        columnfive += i[4]
    decoded = columnone + columntwo + columnthree + columnfour + columnfive
    print(decoded)


message = input("Enter a message: ")
simple_ct(message, 5)
