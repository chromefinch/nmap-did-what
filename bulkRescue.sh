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
print_red "Remember to update both ${SCAN_TITLE}_phase1_Top${topPorts}Ports.gnmap and ${SCAN_TITLE}_phase3_Port_Disco.gnmap with desired target ports"
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
print_yellow "--- Resuming Scan: ${SCAN_TITLE} ---"
print_yellow "--- Using Host List: ${HOST_LIST_FILE} ---"
sleep 3
print_blue "[+] Phase 4: Deep Scan on Live Hosts and Found Ports"
while IFS= read -r IP ; do
    PORT=$(grep -E "$IP \(\)\s+Ports: " ${SCAN_TITLE}_phase3_Port_Disco.gnmap | grep -Eo "[0-9]+\/open" | grep -Eo "[0-9]+" | paste -sd',')
    test -f ./"${SCAN_TITLE}_phase4_DeepScan_HOST_${IP}.nmap" >/dev/null 2>&1 && print_purple "[!] ${IP} already scanned" ||
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
