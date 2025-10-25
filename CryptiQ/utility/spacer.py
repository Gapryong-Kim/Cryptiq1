message = input("Enter message: ").replace(" ", "")
block_length = int(input("block length: "))

def text_spacer(message,block_length):
    message=message.replace(' ','')
    blocked = ""
    for index, i in enumerate(message):
        if (index) % block_length == 0:
            blocked += " "
        blocked += i
    return blocked
