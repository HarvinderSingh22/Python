user_input=int(input("Enter the number:"))
if user_input<1:
    print("Enter Positive integer")
else:
    fact=1
    x=1
    while(x<user_input+1):
        fact*=x
        x+=1
print(f"{user_input} factorial is {fact}")