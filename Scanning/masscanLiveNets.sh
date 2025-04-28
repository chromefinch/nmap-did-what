#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <masscan_output_file>"
  exit 1
fi

while IFS= read -r line; do
  if [[ "$line" =~ Host:\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
    ip="${BASH_REMATCH[1]}"
    subnet=$(echo "$ip" | cut -d'.' -f1-3).0/24
    echo "$subnet"
  fi
done < "$1" | sort -u
