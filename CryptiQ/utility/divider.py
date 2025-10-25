message = input("enter message: ").replace(" ", "")
half = ""
halves = []
for k, i in enumerate(message):
    half += i
    if k + 1 == len(message) / 2:
        halves.append(half)
        half = ""
halves.append(half)
for i in halves:
    print(i)
    print(len(i))
