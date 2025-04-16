#!/bin/bash

# --- Configuration ---
# Set to 1 for case-insensitive keyword matching, 0 for case-sensitive
CASE_INSENSITIVE=1

# --- Script Logic ---
SCRIPT_NAME=$(basename "$0")

# Function to display usage instructions
usage() {
  echo "Usage: ${SCRIPT_NAME} <nmap_xml_file> <keyword_list_file>"
  echo
  echo "Parses an Nmap XML output file (-sn scan recommended) to find hosts"
  echo "whose reverse DNS (PTR record) contains any of the specified keywords."
  echo "Outputs a unique list of /24 subnets containing those hosts."
  echo
  echo "Arguments:"
  echo "  <nmap_xml_file>    : Path to the Nmap XML scan results file."
  echo "  <keyword_list_file>: Path to a file containing keywords, one per line."
  echo
  echo "Requires 'xmlstarlet' to be installed."
}

# Check for correct number of arguments
if [ "$#" -ne 2 ]; then
  usage
  exit 1
fi

NMAP_XML_FILE="$1"
KEYWORD_FILE="$2"

# Check if input files exist and are readable
if [ ! -f "${NMAP_XML_FILE}" ] || [ ! -r "${NMAP_XML_FILE}" ]; then
  echo "Error: Nmap XML file not found or not readable: ${NMAP_XML_FILE}" >&2
  exit 1
fi

if [ ! -f "${KEYWORD_FILE}" ] || [ ! -r "${KEYWORD_FILE}" ]; then
  echo "Error: Keyword file not found or not readable: ${KEYWORD_FILE}" >&2
  exit 1
fi

# Check if xmlstarlet is installed
if ! command -v xmlstarlet &> /dev/null; then
  echo "Error: 'xmlstarlet' command not found. Please install it." >&2
  echo "(e.g., 'sudo apt install xmlstarlet' or 'sudo yum install xmlstarlet')" >&2
  exit 1
fi

echo "INFO: Processing Nmap XML file: ${NMAP_XML_FILE}"
echo "INFO: Using keyword file: ${KEYWORD_FILE}"
echo "INFO: Finding matching hosts and extracting /24 subnets..."

# Use xmlstarlet to extract IP addresses and PTR hostnames for hosts that are 'up'
# Pipe the output to awk for keyword matching and subnet calculation
# Finally, sort uniquely
xmlstarlet sel -t \
    -m "//host[status/@state='up' and hostnames/hostname[@type='PTR']]" \
    -v "address[@addrtype='ipv4']/@addr" \
    -o $'\t' \
    -v "hostnames/hostname[@type='PTR']/@name" \
    -n "${NMAP_XML_FILE}" 2>/dev/null | \
awk -F'\t' -v keywords_file="${KEYWORD_FILE}" -v case_insensitive="${CASE_INSENSITIVE}" '
# BEGIN block: Read keywords from the file into an associative array
BEGIN {
    keyword_count = 0
    while ((getline keyword < keywords_file) > 0) {
        # Skip empty lines
        if (keyword ~ /^[[:space:]]*$/) {
            continue
        }
        # Store keyword (optionally lowercased)
        if (case_insensitive) {
            keywords[tolower(keyword)] = 1
        } else {
            keywords[keyword] = 1
        }
        keyword_count++
    }
    close(keywords_file) # Close the file handle

    if (keyword_count == 0) {
        print "Warning: No keywords loaded from " keywords_file > "/dev/stderr"
    } else {
         print "INFO: Loaded " keyword_count " keywords." > "/dev/stderr"
    }
}

# Main processing block: Executed for each line from xmlstarlet
{
    ip = $1
    hostname = $2
    matched = 0

    # Prepare hostname for comparison based on case sensitivity setting
    compare_hostname = (case_insensitive) ? tolower(hostname) : hostname

    # Iterate through loaded keywords to check for matches
    # This allows matching keywords *within* the hostname, not just exact matches
    for (key in keywords) {
        if (index(compare_hostname, key) > 0) {
            matched = 1
            break # Found a match, no need to check other keywords for this host
        }
    }

    # If a keyword was found in the hostname
    if (matched) {
        # Extract the first three octets for the /24 subnet
        if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { # Basic IPv4 check
             num_parts = split(ip, octets, ".")
             if (num_parts >= 3) {
                 subnet = octets[1] "." octets[2] "." octets[3] ".0/24"
                 print subnet
             }
        } else {
             print "Warning: Skipping non-IPv4 address format found for matched host: " ip > "/dev/stderr"
        }
    }
}
' | sort -u # Sort the resulting subnets and remove duplicates

echo "INFO: Processing complete."

exit 0
