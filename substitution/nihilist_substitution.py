
def depunctuate(ciphertext):
    new_text=''.join(i for i in ciphertext if i.isalpha() or i==' ')
    return new_text


def find_period(message):
    blocks=message.split()
    substrings = []
    ngram = 3
    mode_string = ""
    frequency = 1
    nospace = message.replace(" ", "")

    for i in range(len(nospace) - (ngram - 1)):

        substring = ''.join(x for x in blocks[i : i + ngram])
        substrings.append(substring)
        if nospace.count(substring) > frequency:
            frequency = nospace.count(substring)
            mode_string = substring
    print(mode_string)
    indices = []
    start_index = 0
    for i in range(frequency):
        new_index = blocks.index(mode_string, start_index)
        indices.append(new_index)
        start_index = new_index + ngram

    lengths = []
    for index, i in enumerate(indices[:-1]):
        length = indices[index + 1] - indices[index]
        lengths.append(length)
    factors = []
    for i in lengths:
        for x in range(2, i):
            if i % x == 0:
                factors.append(x)
    common_factors = factors.copy()
    for factor in factors:
        for length in lengths:
            if length % factor != 0:
                common_factors.remove(factor)
                break
    common_factors = list(set(common_factors))
    lengths = sorted([i for i in common_factors])
    return lengths


ciphertext=input('enter ciphertext: ')
print(find_period(ciphertext))
