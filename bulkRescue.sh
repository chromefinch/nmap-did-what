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
echo "kickoff phase 4 with modifed files or if there was crash. "
read -p "Enter the previous Scan Title to resume: " SCAN_TITLE
read -p "Enter the path to the host list file: " HOST_LIST_FILE
read -p "How many parallel scans should we run in phase4? " howmany

topPorts=$(ls -1 | grep "${SCAN_TITLE}_phase1_Top"*"Ports.gnmap" | grep -Eo "[0-9]+Ports\.gnmap" | grep -Eo "[0-9]+")
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
# --- Phase 4: Deep Scan (Version/Script/OS) on Live Hosts & Found Ports ---
print_blue "[+] Phase 4: Deep Scan on Live Hosts and Found Ports"
export SCAN_TITLE topPorts # Export variables needed inside parallel
cat "${SCAN_TITLE}_live_hosts.txt" | parallel -j $howmany --line-buffered '
    IP="{}"
    PORT=$(grep -E "$IP \(\)\s+Ports: " "${SCAN_TITLE}_phase3_Port_Disco.gnmap" | grep -Eo "[0-9]+\/open" | grep -Eo "[0-9]+" | paste -sd\',')
    if [[ -z "$PORT" ]]; then
        PORT=$(grep -E "$IP \(\)\s+Ports: " "${SCAN_TITLE}_phase1_Top${topPorts}Ports.gnmap" | grep -Eo "[0-9]+\/open" | grep -Eo "[0-9]+" | paste -sd\',')
        if [[ -z "$PORT" ]]; then
            echo -e "\033[0;31mNo open ports found for ${IP}. Skipping Deep Scan.\033[0m"
            exit 0
        fi
    fi
    test -f ./"${SCAN_TITLE}_phase4_DeepScan_HOST_${IP}.nmap" && echo -e "\033[0;35m${IP} already scanned\033[0m" || {
        echo -e "\033[0;34m[*] Starting scan ${IP} -p ${PORT}\033[0m"
        nmap -A -T4 --max-retries 3 --max-rtt-timeout 300ms --host-timeout 8m -Pn "$IP" -p "$PORT" -oA "${SCAN_TITLE}_phase4_DeepScan_HOST_${IP}"
    }
'


print_green "[+] Phase 4 complete"
