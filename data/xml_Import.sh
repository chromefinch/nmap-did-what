#!/usr/bin/env bash

echo "Script to bulk import xml's using a for loop & the nmap-to-sqlite.py script" 

# Check if the user is running with sudo
if [[ "$EUID" -eq 0 ]]; then
  echo "Listing directory structure (directories only, up one level):"
  ls -1dR ../*
  echo ""
else
    # Check if the 'tree' command is installed
    if command -v tree &> /dev/null; then
    echo "Listing directory structure (directories only, up one level):"
    tree -d ../
    echo ""
    fi
fi

# Prompt the user for the location of the XML files
read -p "Enter the folder where the .xml files are located: " folder

# Check if the entered folder exists
if [ ! -d "$folder" ]; then
  echo "Error: Folder '$folder' does not exist."
  exit 1
fi

# Loop through all .xml files in the specified folder
for file in "$folder"/*.xml; do
  if [ -f "$file" ]; then
    echo "Processing file: $file"
    python3 nmap-to-sqlite.py "$file"
    if [ $? -ne 0 ]; then
      echo "Error: python3 nmap-to-sqlite.py '$file' failed."
    fi
  fi
done

echo "Processing complete."
