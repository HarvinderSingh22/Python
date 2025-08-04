hardcode="python123"
i=1

while i<=3:
    
    user_input=input("Enter the password:")
    if user_input==hardcode:    
       print("Login Successful")
       break
    else:
     print("Account Locked")
     i+=1