user_input=int(input("Enter the number:"))
sum=0
x=1
while x<=user_input:
    # print(sum)
    sum+=x
    x+=1
    if(sum>=100):
      break
else:
    print(sum)
