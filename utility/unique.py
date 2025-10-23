def unique(message):
    lengths=[]
    for block_length in range(1, 100):
        blocked = ""
        for index, i in enumerate(message):
            if (index) % block_length == 0:
                blocked += " "
            blocked += i
        lengths.append(f"{block_length}: {len(list(set(blocked.split())))}")
    return lengths
