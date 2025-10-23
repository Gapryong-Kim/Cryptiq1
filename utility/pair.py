message = input("Enter a message: ").replace(" ", "")
paired = ""
for i, k in enumerate(message):
    if (i) % 2 == 0:
        paired += " "
    paired += k

print(paired)
