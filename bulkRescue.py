#!/usr/bin/env python3

import os
import sys
import subprocess
import re
import time
import getpass
import glob
from concurrent.futures import ProcessPoolExecutor, as_completed

# --- Color Printing Functions ---
def print_color(text, color_code):
    """Prints text in a specified color."""
    # Ensure we flush immediately, important for \r updates
    print(f"\033[{color_code}m{text}\033[0m", flush=True)

def print_green(text):
    print_color(text, "0;32")

def print_yellow(text):
    print_color(text, "0;33")

def print_red(text):
    print_color(text, "0;31")

def print_blue(text):
    print_color(text, "0;34")

def print_purple(text):
    print_color(text, "0;35")

# --- Helper Functions ---
def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def find_top_ports(scan_title):
    """Finds the 'Top X Ports' number from phase 1 gnmap files."""
    try:
        pattern = f"{re.escape(scan_title)}_phase1_Top*Ports.gnmap"
        matching_files = glob.glob(pattern)
        if not matching_files:
            print_red(f"Warning: No phase 1 Top Ports file found matching pattern '{pattern}'.")
            return None
        # Simple approach: use the first one found
        filename = matching_files[0]
        match = re.search(r"_Top(\d+)Ports\.gnmap$", filename)
        if match:
            return match.group(1)
        else:
            print_red(f"Warning: Could not extract port number from filename '{filename}'.")
            return None
    except Exception as e:
        print_red(f"Error finding top ports file: {e}")
        return None

def get_ports_for_ip(ip, gnmap_file):
    """Extracts open ports for a given IP from a gnmap file."""
    ports = []
    try:
        with open(gnmap_file, 'r') as f:
            for line in f:
                if re.match(rf"^Host:\s+{re.escape(ip)}\s*(?:\(\))?\s+.*\s+Ports:\s+", line):
                    found_ports = re.findall(r"(\d+)/open/", line)
                    ports.extend(found_ports)
                    break # Assume only one relevant line per host per file
        # Return unique, numerically sorted ports
        return sorted(list(set(ports)), key=int)
    except FileNotFoundError:
        return [] # Don't warn here, handled by calling logic
    except Exception as e:
        # Print error immediately if it happens during file read/parse
        print_red(f"\nError reading/parsing {gnmap_file} for IP {ip}: {e}")
        return []

def run_nmap_scan(ip, port_string, scan_title):
    """Runs the detailed Nmap scan for a single IP and ports."""
    output_base = f"{scan_title}_phase4_DeepScan_HOST_{ip}"
    output_nmap_file = f"{output_base}.nmap"
    scan_message_prefix = f"Scan for {ip}:" # For consistent result messages

    if os.path.exists(output_nmap_file):
        # Use purple for already scanned, return specific status
        # Note: print_purple might interfere with progress bar, returning status is better
        return f"{scan_message_prefix} Skipped - Output file {output_nmap_file} already exists."

    if not port_string:
        # Use red for no ports, return specific status
        return f"{scan_message_prefix} Skipped - No open ports found in provided gnmap files."

    # Message printed by main loop before task starts might be better
    # print_blue(f"[*] Starting scan {ip} -p {port_string}")
    nmap_command = [
        'nmap', '-A', '-T4',
        '--max-retries', '3',
        '--max-rtt-timeout', '300ms',
        '--host-timeout', '8m',
        '-Pn',
        '-p', port_string,
        ip,
        '-oA', output_base
    ]

    try:
        # Run Nmap, capture output, don't check exit code immediately
        result = subprocess.run(nmap_command, capture_output=True, text=True, check=False)

        if result.returncode == 0:
            # Use green for success, return specific status
            return f"{scan_message_prefix} Scan Successful (Output: {output_base}.*)"
        else:
            # Use red for failure, include stderr if available
            error_details = result.stderr.strip()
            if not error_details and result.stdout.strip(): # Sometimes errors go to stdout
                error_details = result.stdout.strip().splitlines()[-1] # Last line often has summary
            return f"{scan_message_prefix} Scan Failed (Code {result.returncode}). Error: {error_details[:200]}" # Limit error length

    except FileNotFoundError:
        # This is a critical error, should likely stop everything
        # Raise an exception to be caught by the main loop? Or return specific error?
        return f"{scan_message_prefix} CRITICAL ERROR: 'nmap' command not found."
    except Exception as e:
        # Use red for unexpected errors during subprocess execution
        return f"{scan_message_prefix} Scan Error ({type(e).__name__}: {e})"

# --- Main Script Logic ---
if __name__ == "__main__":
    print(f"Current Directory: {os.getcwd()}")
    print("Files in current directory:")
    for item in sorted(os.listdir('.')):
        print(f"- {item}")
    print("-" * 20)

    # --- Root Check ---
    try:
        if os.geteuid() != 0:
            print_red("This script must be run as root (or with sudo)")
            sys.exit(1)
    except AttributeError:
        if os.name != 'posix':
             print_yellow("Warning: Could not check for root privileges on this OS. Ensure you have necessary permissions.")
        else:
             print_red("Could not determine user privileges. Exiting.")
             sys.exit(1)

    # --- User Input ---
    print("Kickoff phase 4 with modified files or if there was crash.")
    scan_title = input("Enter the previous Scan Title to resume: ")
    host_list_file_input = input("Enter the path to the host list file (e.g., scan_live_hosts.txt): ") # Keep user input separate
    while True:
        try:
            how_many_parallel = int(input("How many parallel scans should we run in phase4? "))
            if how_many_parallel > 0:
                break
            else:
                print_red("Please enter a positive number for parallel scans.")
        except ValueError:
            print_red("Invalid input. Please enter a number.")

    # --- Determine Top Ports from Phase 1 ---
    topPorts = find_top_ports(scan_title)
    if topPorts:
         print_red(f"Remember to update both {scan_title}_phase1_Top{topPorts}Ports.gnmap and {scan_title}_phase3_Port_Disco.gnmap with desired target ports")
    else:
         print_yellow("Could not automatically determine Top Ports number from phase 1 files.")
         print_red(f"Ensure {scan_title}_phase3_Port_Disco.gnmap contains all desired target ports.")

    # --- Input Validation ---
    if not scan_title:
      print_red("Error: Scan title cannot be empty.")
      sys.exit(1)
    # Validate the file provided by the user, even if we use _live_hosts.txt later
    if not os.path.isfile(host_list_file_input):
      print_red(f"Error: Input host list file '{host_list_file_input}' not found.")
      sys.exit(1)

    # Define primary files based on scan_title
    live_hosts_file = f"{scan_title}_live_hosts.txt"
    phase3_gnmap = f"{scan_title}_phase3_Port_Disco.gnmap"
    phase1_gnmap = f"{scan_title}_phase1_Top{topPorts}Ports.gnmap" if topPorts else None

    if not os.path.isfile(live_hosts_file):
      print_red(f"Error: Live hosts file '{live_hosts_file}' not found based on Scan Title.")
      print_yellow(f"Ensure the live hosts file exists (expected name based on scan title). It should contain one IP per line.")
      sys.exit(1)

    clear_screen()
    print_yellow(f"--- Resuming Scan: {scan_title} ---")
    print_yellow(f"--- Using Live Hosts From: {live_hosts_file} ---")
    print_yellow(f"--- Running {how_many_parallel} scans in parallel ---")
    if phase1_gnmap and os.path.exists(phase1_gnmap): # Only mention if it exists
        print_yellow(f"--- Phase 1 Top Ports File: {phase1_gnmap} ---")
    else:
        print_yellow(f"--- Phase 1 Top Ports File: Not found or not determined ---")
    if os.path.exists(phase3_gnmap):
         print_yellow(f"--- Phase 3 Port Disco File: {phase3_gnmap} ---")
    else:
         print_red(f"--- Phase 3 Port Disco File: {phase3_gnmap} (Not found!) ---")
         # Decide whether to exit if phase 3 file is missing
         # sys.exit(1)

    time.sleep(3)

    # --- Phase 4: Deep Scan ---
    try:
        with open(live_hosts_file, 'r') as f:
            live_ips = [line.strip() for line in f if line.strip() and not line.startswith('#')] # Ignore empty lines/comments
        if not live_ips:
            print_yellow(f"Live hosts file '{live_hosts_file}' is empty or only contains comments. No hosts to scan.")
            sys.exit(0)
    except Exception as e:
        print_red(f"Error reading live hosts file {live_hosts_file}: {e}")
        sys.exit(1)

    total_tasks = len(live_ips)
    tasks = []
    results = [] # Store result messages
    completed_count = 0

    print_blue(f"\n[+] Phase 4: Starting Deep Scan on {total_tasks} Live Hosts")

    # Prepare arguments for each task beforehand
    scan_args = []
    print_blue("Preparing scan tasks...")
    for ip in live_ips:
        ports = get_ports_for_ip(ip, phase3_gnmap)
        if not ports and phase1_gnmap and os.path.exists(phase1_gnmap):
            ports = get_ports_for_ip(ip, phase1_gnmap)
        port_string = ",".join(ports)
        scan_args.append((ip, port_string, scan_title)) # Tuple of args for run_nmap_scan

    # Use ProcessPoolExecutor for parallel execution
    with ProcessPoolExecutor(max_workers=how_many_parallel) as executor:
        print_blue(f"Submitting {total_tasks} scan jobs to the pool...")
        # Submit tasks using prepared arguments
        tasks = [executor.submit(run_nmap_scan, *args) for args in scan_args]

        print_blue("Waiting for scans to complete...")
        # Initial progress print
        if total_tasks > 0:
             # Use print directly to allow \r
             print(f"\rProgress: 0.0% (0/{total_tasks})", end='', flush=True)

        # Process results as they complete
        for future in as_completed(tasks):
            completed_count += 1
            percentage = (completed_count / total_tasks) * 100 if total_tasks > 0 else 100
            # Format progress string
            progress_string = f"Progress: {percentage:.1f}% ({completed_count}/{total_tasks})"

            try:
                result_message = future.result() # Get return value from run_nmap_scan
                results.append(result_message)

                # Print progress update, overwriting the line. Add padding.
                print(f"\r{progress_string:<60}", end='', flush=True) # Pad to ensure full overwrite

                # Optionally print result summary conditionally (e.g., only errors)
                if "Failed" in result_message or "Error" in result_message:
                    # Print errors on a new line so they don't get overwritten
                    print() # Move cursor to next line
                    print_red(result_message)
                    # Reprint progress bar after error message
                    print(f"\r{progress_string:<60}", end='', flush=True)
                elif "Skipped - Output file" in result_message:
                    print()
                    print_purple(result_message)
                    print(f"\r{progress_string:<60}", end='', flush=True)


            except Exception as exc:
                # Handle exceptions *from the future itself* (e.g., worker process crash)
                # This is different from errors returned *by* run_nmap_scan
                completed_count += 1 # Still counts as completed task, albeit failed
                percentage = (completed_count / total_tasks) * 100 if total_tasks > 0 else 100
                progress_string = f"Progress: {percentage:.1f}% ({completed_count}/{total_tasks})"

                print() # Move cursor to next line before printing error
                print_red(f'\nCRITICAL TASK FAILURE (IP processing might have crashed): {exc}')
                results.append(f"Task Error: {exc}")
                 # Reprint progress bar
                print(f"\r{progress_string:<60}", end='', flush=True)


    # Final newline after the loop completes to ensure cursor is on a new line
    print()
    print_green("[+] Phase 4 complete")

    # Optional: Print a summary of results
    # print("\n--- Scan Summary ---")
    # successes = sum(1 for r in results if "Successful" in r)
    # skips_exist = sum(1 for r in results if "Skipped - Output file" in r)
    # skips_noport = sum(1 for r in results if "Skipped - No open ports" in r)
    # fails = sum(1 for r in results if "Failed" in r or "Error" in r)
    # print_green(f"Successful Scans: {successes}")
    # print_purple(f"Skipped (Already Done): {skips_exist}")
    # print_yellow(f"Skipped (No Ports Found): {skips_noport}")
    # print_red(f"Failures/Errors: {fails}")
