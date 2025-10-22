message = input("Enter a message: ")

while True:
    to_replace = input("Enter chracter to replace: ")
    replacement = input("Enter replacement character: ")
    message = message.replace(to_replace, replacement)
    try_again = input("Again?(y/n) ")
    if try_again == "n":
        break

print(message)
