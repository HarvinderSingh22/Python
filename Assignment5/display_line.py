def display_line(input_file):
    try:
        with open(input_file, "r") as file:
            lines = file.readlines()
            for i in range(len(lines)):
             print(f"{i + 1}: {lines[i].strip()}")

    except FileNotFoundError:
        print("File not found")
    except Exception as e:
        print(f"Error: {e}")

display_line("data.txt")
