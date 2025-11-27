def nospace(text,remove_punctuation):
    if remove_punctuation:
        return ''.join(i for i in text if i.isalpha() or i.isnumeric()).lower()
    else:
        return text.replace(' ','')
    
def remove_punc(text):
    return ''.join(i for i in text if i.isalpha() or i==' ' or i.isnumeric())
