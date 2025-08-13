def prime_number(n):
 if n<=1:
    print(f"{n} is not a prime number.")
 else:
    for x in range(2,(n**2)):
        if n%x==0:
            print(f"{n} is not prime number.")
            break
        else:
            print(f"{n} is a prime number.")
            break
 return n
num=int(input("Enter the number:"))
prime_number(num)
