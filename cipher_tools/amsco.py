from itertools import permutations
common_words = [
    'dog',
    'barking',
    "the",
    "be",
    "to",
    "of",
    "and",
    "a",
    "in",
    "that",
    "have",
    "I",
    "it",
    "for",
    "not",
    "on",
    "with",
    "he",
    "as",
    "you",
    "do",
    "at",
    "this",
    "but",
    "his",
    "by",
    "from",
    "they",
    "we",
    "say",
    "her",
    "she",
    "or",
    "an",
    "will",
    "my",
    "one",
    "all",
    "would",
    "there",
    "their",
    "what",
    "so",
    "up",
    "out",
    "if",
    "about",
    "who",
    "get",
    "which",
    "go",
    "me",
    "when",
    "make",
    "can",
    "like",
    "no",
    "just",
    "him",
    "know",
    "take",
    "into",
    "your",
    "good",
    "some",
    "could",
    "them",
    "see",
    "other",
    "than",
    "then",
    "now",
    "look",
    "only",
    "come",
    "its",
    "over",
    "think",
    "also",
    "back",
    "after",
    "use",
    "two",
    "how",
    "our",
    "work",
    "first",
    "well",
    "way",
    "even",
    "new",
    "want",
    "because",
    "any",
    "these",
    "give",
    "day",
    "most",
    "us",
]


def depunctuate(ciphertext):
    new_text=''.join(i for i in ciphertext if i.isalpha()).lower()
    return new_text


def splitter(string,config):
    start_index=0
    
    strings=[]
    for i in config:
        try:
            num=int(i)
            base=''
            base+=string[start_index:start_index+num]
            start_index+=num
            strings.append(base)
        except Exception:
            strings.append(string[-1])
    return strings


def generate_grid(key_length,text_length,convention):
    
    start=convention[0]
    pattern=[convention[0] if i%2!=0 else convention[1] for i in range(1,key_length+1)]
    toggle=-1
    grid=pattern.copy()
    count=0
    if key_length%2==1:
        while sum(grid)<text_length:
                grid.append(grid[-2])
    else:
        while sum(grid)<text_length:
            grid+=pattern[::toggle]
            toggle*=-1
        while sum(grid)>text_length:
            temp=grid[-1]
            grid=grid[:-1]
            if sum(grid)<text_length:
                grid.append(text_length-sum(grid))
                
                break
    return grid


def amsco_break(text):
    original_message = text

    text=''.join(i for i in text if i.isalpha()).lower()
    conventions=[(1,2),(2,1)]
    finalists=[]
    for convention in conventions:
        candidates=[]
        for length in range(2,7):       
            
            
            perms = list(set(permutations(range(1, length+1))))
            pattern=[convention[0] if i%2!=0 else convention[1] for i in range(1,length+1)]
            grid=pattern.copy()
            sums=sum(grid)
            index=0
            possibilities=[]
            count=1
            grid=generate_grid(length,len(text),convention)
            for perm in perms:
                decoded=''
                columns=[]
                for num in perm:
                    column=[]
                    column.append(num)
                    config=''
                    for i,k in enumerate(grid):
                        if i%length==perm.index(num):
                            config+=str(k) 
                    column.append(config)
                    columns.append(column)            
                
                column_list=sorted(columns,key=lambda x:x[0])
                
                start_index=0
                column_strings=[]
                for number,pattern in column_list:
                    column_decode=''
                    column_characters=sum(int(i) for i in pattern)
                    if start_index<len(text):
                        column_decode+=text[start_index:(column_characters+start_index)]
                        start_index+=column_characters
                    else:
                        column_decode+=text[start_index:]
                    column_strings.append((number,column_decode))
                    
                ordered_decode=[]
                
            
                for i,k in enumerate(perm):
                    ordered_decode.append(column_strings[k-1][1])
                
                
                decoded_columns=[]
                for i,k in enumerate(columns):
                    decoded_columns.append(splitter(ordered_decode[i],k[1]))
                temp=decoded_columns.copy()
                temp.sort(key=lambda x:len(x))
                max_length=len(temp[-1]) 
                for i,k in enumerate(decoded_columns):
                    if len(k)<max_length:
                        decoded_columns[i].append('')
                final_decode=''
                for i in range(max_length):
                    for x in decoded_columns:
                        final_decode+=x[i]
                        
                probability=sum(final_decode.count(i) for i in common_words)
                possibilities.append((probability,final_decode,perm,convention))
                
                
            
            sorted_possibilities=sorted(possibilities,key=lambda x:x[0],reverse=True)
            
            final_candidate=sorted_possibilities[0]
            candidates.append(final_candidate)
        rankings=sorted(candidates,key=lambda x:x[0],reverse=True)
        finalists.append(rankings[0])
    final_rankings=sorted(finalists,key=lambda x:x[0],reverse=True)
    final_msg=final_rankings[0][1]
    final_key=final_rankings[0][2:]
    final_key= f' {final_key[0]}, convention: {final_key[1]}'
    restored = []
    letter_index = 0
    for ch in original_message:
        if ch.isalpha():
            # Preserve original case
            new_char = final_msg[letter_index]
            restored.append(new_char.upper() if ch.isupper() else new_char)
            letter_index += 1
        else:
            restored.append(ch)
    restored_text = ''.join(restored)
    return final_key,restored_text


       

