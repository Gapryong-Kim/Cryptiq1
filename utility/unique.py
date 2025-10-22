message = input("Enter message: ").replace(" ", "")
for block_length in range(1, 200):
    blocked = ""
    for index, i in enumerate(message):
        if (index) % block_length == 0:
            blocked += " "
        blocked += i
    print(f"{block_length}: {len(list(set(blocked.split())))}")
