#!/bin/bash

# Prompt the user for the large list file
echo "Enter the filename of the large list (Full list):"
read large_list_file

# Check if the large list file exists
if [ ! -f "$large_list_file" ]; then
  echo "Error: File '$large_list_file' not found."
  exit 1
fi

# Prompt the user for the remove list file
echo "Enter the filename of the list to remove (already scanned):"
read remove_list_file

# Check if the remove list file exists
if [ ! -f "$remove_list_file" ]; then
  echo "Error: File '$remove_list_file' not found."
  exit 1
fi

# Prompt the user for the output file
echo "Enter the filename for the new list (output):"
read new_list_file

# Initialize new_list_file, useful in case it already exists.
> "$new_list_file"

# Process the large list and filter out items from the remove list
while IFS= read -r item; do
  if ! grep -Fxq "$item" "$remove_list_file"; then
    echo "$item" >> "$new_list_file"
  fi
done < "$large_list_file"

# Inform the user of the successful completion
echo "Successfully created '$new_list_file' with filtered items."

exit 0
