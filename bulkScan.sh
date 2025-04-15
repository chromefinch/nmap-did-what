#!/usr/bin/env bash
pwd
ls -1

print_green (){
	echo -e "\033[0;32m$1\033[0m"
}
print_yellow (){
	echo -e "\033[0;33m$1\033[0m"
}
print_red (){
	echo -e "\033[0;31m$1\033[0m"
}
print_blue (){
	echo -e "\033[0;34m$1\033[0m"
}
print_purple (){
	echo -e "\033[0;35m$1\033[0m"
}

if [[ $EUID -ne 0 ]]; then
    print_red "This script must be run as root"
        exit 1
fi

# --- User Input ---
read -p "Enter a unique scan title (e.g., ProjectX_Q1_Scan): " SCAN_TITLE
read -p "Enter the path to the host list file: " HOST_LIST_FILE
read -p "Enter number of --top-ports: " topPorts
read -p "Enter a port to exclude (if this port is the only live port, scans will be excluded): " ignore
Phase3default="-p-"
echo "Phase 3 does a complete port discovery $Phase3default, you can overwrite that here (-p-/--top-ports X/skip) " 
read -p "Skip will use results from Phase 2, I reccomend skipping or setting something other than -p-: " Phase3Answer
Phase3=${Phase3Answer:-$Phase3default}

# --- Input Validation ---
if [[ -z "$SCAN_TITLE" ]]; then
  print_red "Error: Scan title cannot be empty."
  exit 1
fi
if [[ ! -f "$HOST_LIST_FILE" ]]; then
  print_red "Error: Host list file '$HOST_LIST_FILE' not found."
  exit 1
fi
clear
print_yellow "--- Starting Scan: ${SCAN_TITLE} ---"
print_yellow "--- Using Host List: ${HOST_LIST_FILE} ---"

# --- Phase 1: Discovery (SYN Scan, Top X, No Ping) ---
print_blue "[+] Phase 1: Discovery Scan (Top $topPorts Ports, No Ping)"
nmap -sS -T4 --max-retries 1 --max-rtt-timeout 300ms --host-timeout 1m --max-scan-delay 5 --min-rate 800 -Pn -n \
     -iL "${HOST_LIST_FILE}" \
     --top-ports $topPorts \
     -oA "${SCAN_TITLE}_phase1_Top${topPorts}Ports"

# --- Phase 2: Ping Sweep (Optional - Run against original list) ---
print_blue "[+] Phase 2: Ping Sweep on original list"
nmap -sn -T4 --max-retries 1 --max-rtt-timeout 300ms --host-timeout 5m -n \
     -iL "${HOST_LIST_FILE}" \
     -oA "${SCAN_TITLE}_phase2_PingSweep"

# --- Extract Live Hosts (Primarily from Phase 1 SYN Scan) ---
print_blue "[+] Extracting Live Hosts found in Phases 1 & 2"
# Using .nmap output; consider using .gnmap 'Status: Up' for potentially more reliable parsing
grep -E "Ports: [0-9]+" "${SCAN_TITLE}_phase1_Top${topPorts}Ports.gnmap" | grep open | awk '!/$ignore/' | awk '{print $2}' > "${SCAN_TITLE}_live_hosts.txt"
# Optional: Add hosts found *only* by Phase 2 ping sweep if needed
grep "Host: " "${SCAN_TITLE}_phase2_PingSweep.gnmap" | awk '{print $2}' >> "${SCAN_TITLE}_live_hosts.txt"
sort -u "${SCAN_TITLE}_live_hosts.txt" -o "${SCAN_TITLE}_live_hosts.txt" # Keep unique if merging

if [[ ! -s "${SCAN_TITLE}_live_hosts.txt" ]]; then
    print_red "[!] Warning: No live hosts found in Phase 1 based on grep pattern."
    # Consider exiting or modifying logic if no hosts are found
else
    print_green "[+] Live hosts saved to ${SCAN_TITLE}_live_hosts.txt"
fi

# --- Phase 3: Discover all ports ---
phaseThree(){
print_blue "[+] Phase 3: Scan All Ports on Live Hosts"
if [[ -s "${SCAN_TITLE}_live_hosts.txt" ]]; then
    nmap -sS -Pn -n -T4 --max-retries 2 --max-rtt-timeout 300ms --host-timeout 15m  --max-scan-delay 5 --min-rate 800 \
         -iL "${SCAN_TITLE}_live_hosts.txt" \
         $Phase3 \
         -oA "${SCAN_TITLE}_phase3_Port_Disco"
else
    print_red "[!] Skipping Phase 3: No live hosts found in ${SCAN_TITLE}_live_hosts.txt."
fi
}

case $Phase3 in
    skip) print_blue "[+] using previously discovered ports from Phase 1"
        cp ${SCAN_TITLE}_phase1_Top${topPorts}Ports.gnmap ${SCAN_TITLE}_phase3_Port_Disco.gnmap
        echo "Due to Phase 3 being skipped, this was copped from phase 1" >> ${SCAN_TITLE}_phase3_Port_Disco.gnmap ;;
    *) phaseThree ;;
esac

# --- Extract Open Ports (From Phase 3 Scan Results) ---
print_blue "[+] Extracting Open Ports discovered in Phase 3"
# grep "^[0-9]\+\/.*state open" "${SCAN_TITLE}_phase3_Port_Disco.gnmap" | awk -F '/' '{print $1}' | sort -nu > "${SCAN_TITLE}_open_ports.txt"
# Alternative using .gnmap (often more reliable):
grep -Eo "[0-9]+\/open" ${SCAN_TITLE}_phase3_Port_Disco.gnmap | grep -Eo "[0-9]+" | sort -nu | paste -sd',' > "${SCAN_TITLE}_open_ports.txt"

if [[ ! -s "${SCAN_TITLE}_open_ports.txt" ]]; then
    print_red "[!] Warning: No open ports found in Phase 3 scan results."
else
    print_green "[+] Open ports saved to ${SCAN_TITLE}_open_ports.txt"
fi

# --- Phase 4: Deep Scan (Version/Script/OS) on Live Hosts & Found Ports ---
print_blue "[+] Phase 4: Deep Scan on Live Hosts and Found Ports"
while IFS= read -r IP ; do
    PORT=$(grep -E "$IP \(\)\s+Ports: " ${SCAN_TITLE}_phase3_Port_Disco.gnmap | grep -Eo "[0-9]+\/open" | grep -Eo "[0-9]+" | paste -sd',')
    if [[ -n "$PORT" ]]; then
        print_blue "[*] Sarting scan ${IP} -p ${PORT}"
        nmap -A -T4 --max-retries 3 --max-rtt-timeout 300ms --host-timeout 8m -Pn \
                "$IP" \
                -p "$PORT" \
                -oA "${SCAN_TITLE}_phase4_DeepScan_HOST_${IP}"
    else
        # No ports found - print message and skip nmap for this IP
        print_red "[!] No open ports found for ${IP} in ${SCAN_TITLE}_phase3_Port_Disco.gnmap. Trying Phase 1 sweep."
        PORT=$(grep -E "$IP \(\)\s+Ports: " ${SCAN_TITLE}_phase1_Top${topPorts}Ports.gnmap | grep -Eo "[0-9]+\/open" | grep -Eo "[0-9]+" | paste -sd',')
        if [[ -n "$PORT" ]]; then
            print_blue "[*] Sarting scan ${IP} -p ${PORT}"
                nmap -A -T4 --max-retries 3 --max-rtt-timeout 300ms --host-timeout 8m -Pn \
                        "$IP" \
                        -p "$PORT" \
                        -oA "${SCAN_TITLE}_phase4_DeepScan_HOST_${IP}"
        else
            print_red "[!] No open ports found for ${IP} in ${SCAN_TITLE}_phase1_Top${topPorts}Ports.gnmap. Skipping Deep Scan."
        fi
    fi
done < "${SCAN_TITLE}_live_hosts.txt"
print_green "[+] Phase 4 complete"

# This is sloppy, but hopefully it imports to 
combine_nmap_xml() {
  local output_file="${SCAN_TITLE}_Combined_DeepScan.xml"
  local input_files

  # Find all matching XML files and store them in an array
  input_files=($(find . -maxdepth 1 -name "${SCAN_TITLE}_phase4_DeepScan_HOST_*.xml" -print0 | xargs -0))

  if [ ${#input_files[@]} -eq 0 ]; then
    echo "Warning: No input XML files found matching './${SCAN_TITLE}_phase4_DeepScan_HOST_*.xml'." >&2
    # Optionally create an empty output file or exit with a different code
    touch "$output_file"
    return 0
  fi

  echo "Combining the following Nmap XML files into '$output_file':"
  for file in "${input_files[@]}"; do
    if [ -f "$file" ]; then
      echo "- $file"
    else
      echo "Warning: Input file '$file' not found and will be skipped." >&2
    fi
  done

  # Create the root <nmaprun> element in the output file
  echo '<?xml version="1.0" encoding="UTF-8"?>' > "$output_file"
  echo "<nmaprun scanner=\"nmap\" args=\"\" start=\"$(date +%s)\" version=\"7.xx\" xmloutputversion=\"1.04\">" >> "$output_file"
  echo '<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>' >> "$output_file" # Generic scan info

  # Loop through the input files and extract the <host> elements
  for file in "${input_files[@]}"; do
    if [ -f "$file" ]; then
      # Use awk to extract the <host>...</host> blocks, ensuring proper XML structure
      awk '/<host /,/<\/host>/ { if ($0 !~ /<host .*up="down"/) print }' "$file" >> "$output_file"
    fi
  done

  # Close the root <nmaprun> element
  echo '</nmaprun>' >> "$output_file"

  echo "Successfully combined Nmap XML files into '$output_file'."
  return 0
}

#combining them is trash, copy the *_HOST*.xml to the docker data dir use the following:
#for file in *.xml; do python3 nmap-to-sqlite.py "$file"; done
#print_yellow "[+] combining xml"
#combine_nmap_xml

print_blue "--- Scan ${SCAN_TITLE} Complete ---"
