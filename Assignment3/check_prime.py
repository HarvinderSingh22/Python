
user_input=int(input("Enter the number:"))
if user_input<=1:
    print(f"{user_input} is not a prime number.")
else:
    for x in range(2,(user_input**2)):
        if user_input%x==0:
            print("Not Prime")
            break
        else:
            print(f"{user_input} is a prime number.")
            break
        