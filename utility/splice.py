message1 = input("Enter a message: ").replace(" ", "")
message2 = input("Enter a message: ").replace(" ", "")
messages = [message1, message2]
decoded = ""
for i in list(zip(*messages)):
    for x in i:
        decoded += x
print()
print(decoded)
