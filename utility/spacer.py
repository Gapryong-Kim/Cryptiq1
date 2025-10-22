message = input("Enter message: ").replace(" ", "")
block_length = int(input("block length: "))
blocked = ""
for index, i in enumerate(message):
    if (index) % block_length == 0:
        blocked += " "
    blocked += i
print(blocked)
