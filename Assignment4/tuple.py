# Create a tuple of 5 items
my_tuple = ("apple", "banana", "cherry", "date", "mango")
print(f"Original tuple: {my_tuple}")

# Demonstrate indexing
first_item = my_tuple[0]
third_item = my_tuple[2]
last_item = my_tuple[-1] # Negative indexing
print(f"First item (index 0): {first_item}")
print(f"Third item (index 2): {third_item}")
print(f"Last item (negative index -1): {last_item}")

# Demonstrate slicing
slice_from_second_to_fourth = my_tuple[1:4] # Items from index 1 up to (but not including) index 4
slice_from_beginning_to_third = my_tuple[:3] # Items from the beginning up to (but not including) index 3
slice_from_third_to_end = my_tuple[2:] # Items from index 2 to the end
print(f"Slice from second to fourth item: {slice_from_second_to_fourth}")
print(f"Slice from beginning to third item: {slice_from_beginning_to_third}")
print(f"Slice from third item to end: {slice_from_third_to_end}")

# Demonstrate unpacking
item1, item2, item3, item4, item5 = my_tuple
print(f"Unpacked items: {item1}, {item2}, {item3}, {item4}, {item5}")