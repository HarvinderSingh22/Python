user_input=int(input("Enter the number:"))
if user_input<1:
    print("Please enter the number between 1 to 20")
else:
    for x in range(1,21):
        if x==user_input:
            continue
        else:
            print(x)