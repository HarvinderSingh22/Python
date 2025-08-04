def number_sum(num):
    add=0
    while num>0:
     digit = num%10   
     add += digit
     num = num//10
    return add