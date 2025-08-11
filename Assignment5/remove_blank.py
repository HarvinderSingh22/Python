def remove_blank(input_file):
    with open(input_file,"r") as infile:
        lines=infile.readlines()
    cleaned_lines = [line for line in lines if line.strip()]
    with open("cleaned_data.txt","w") as outfile:
        outfile.writelines(cleaned_lines)
remove_blank("data.txt")
     
    