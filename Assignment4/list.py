mylist=[11,121,1221,13331,1.23]
mylist.append(12)  # append the elements,so i added 12 from mylist
print(f"After append elements from list {mylist}")
mylist.remove(121) # remove an elements,so i remove 121 from mylist
print(f"After remove elements from list {mylist}")
mylist.sort(reverse=True) #reverse=True sort the list in descending order
print(f"After sort elements in descending order from list {mylist}")
Sum=sum(mylist)  # sum use for add all elements of list
avg=Sum/len(mylist) #len(mylist) use for find lenght in list
print(f"Sum: {Sum}")
print(f"Average: {avg}")