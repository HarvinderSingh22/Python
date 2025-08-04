
fruits = {"apple", "banana", "orange", "apple"}  # 'apple' is duplicated

print("Initial set of fruits:", fruits)  # Duplicate 'apple' will appear only once

# Step 2: Add a new fruit
fruits.add("mango")
print("After adding mango:", fruits)

# Step 3: Remove a fruit
fruits.remove("banana")
print("After removing banana:", fruits)

# Demonstrate that duplicates are removed
fruits.add("orange")  # Adding 'orange' again, should have no effect
print("After attempting to add duplicate orange:", fruits)
