message = input("Enter message: ").replace(" ", "")
unique_chars = [str(i) for i in range(11)]
frequency = []
for i in unique_chars:
    frequency_pair = (i, message.count(i))
    frequency.append(frequency_pair)
frequency.sort(key=lambda x: x[1], reverse=True)
print(frequency)
