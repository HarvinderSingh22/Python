#Step 1 : Creating a dictionary for students
students={
    "Harry":88,
    "Bhavya":87,
    "Kanishk":85
}

print("Initial student records:", students)

# Step 2 : Add a new student entry
students["Raj"]=78
print(f"After adding raj {students}")

#Step 3 : Update a Harry Marks
students["Harry"]=90
print(f"After updating Harry {students}")

#Step 4 : Delete a Kanishk Entry
del students["Kanishk"]
print(f"After delete Kanishk {students}")

#Step 5 : find the student with highest marks

top_student=max(students,key=students.get)
print(f"Top student is {top_student} with marks {students[top_student]}")