import pyperclip

msg = input("enter a massage: ")
nospace = msg.replace(" ", "")
print(nospace)
pyperclip.copy(nospace)
print("Copied to clipboard.")
