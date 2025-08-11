import string
def count_word(file_input):
    with open(file_input,"r") as file:
        text= file.read().lower()
        for i in string.punctuation:
            text=text.replace(i,"")
        counts={}
        for word in text.split():
            counts[word]=counts.get(word,0)+1
    print(counts)
count_word("data.txt")


