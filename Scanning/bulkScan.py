#!/usr/bin/env python3

import os
import sys
import subprocess
import re
import time
import getpass
import glob
import shutil
import xml.etree.ElementTree as ET
from concurrent.futures import ProcessPoolExecutor, as_completed

# --- Color Printing Functions ---
# (Reusing the same functions as before)
def print_color(text, color_code):
    """Prints text in a specified color."""
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

def run_nmap_command(nmap_args, description="Running Nmap"):
    """Runs an Nmap command using subprocess, prints status, and checks result."""
    print_blue(f"[+] {description}")
    print_yellow(f"    Command: {' '.join(nmap_args)}")
    try:
        # Use subprocess.run, capture output, don't check immediately
        result = subprocess.run(nmap_args, capture_output=True, text=True, check=False)

        if result.returncode == 0:
            print_green(f"    Nmap command completed successfully.")
            # print(result.stdout) # Optionally print stdout
            return True
        else:
            print_red(f"    Nmap command failed with exit code {result.returncode}.")
            print_red(f"    Stderr: {result.stderr.strip()}")
            # print_red(f"    Stdout: {result.stdout.strip()}") # Might contain useful info too
            return False
    except FileNotFoundError:
        print_red("    Error: 'nmap' command not found. Make sure Nmap is installed and in PATH.")
        sys.exit(1) # Nmap is essential, exit if not found
    except Exception as e:
        print_red(f"    An unexpected error occurred running Nmap: {e}")
        return False

def parse_gnmap_for_live_hosts(gnmap_file, ignore_port_str):
    """
    Parses a GNMAP file to find hosts with open ports, excluding hosts
    where the *only* open port is the ignore_port.
    """
    live_hosts = set()
    ignore_port = ignore_port_str if ignore_port_str.isdigit() else None

    try:
        with open(gnmap_file, 'r') as f:
            for line in f:
                if line.startswith('#') or "Status: Down" in line:
                    continue

                # Match lines indicating a host and its ports
                match = re.match(r"Host:\s+(\S+)\s+\(.*\)\s+Ports:\s+(.*)", line)
                if match:
                    ip = match.group(1)
                    ports_section = match.group(2)

                    # Find all open ports for this host in this line
                    open_ports = re.findall(r"(\d+)/open/", ports_section)

                    if open_ports: # Host has at least one open port
                        if ignore_port:
                            # Check if the *only* open port(s) is the ignored one
                            is_only_ignored = all(p == ignore_port for p in open_ports)
                            if not is_only_ignored:
                                live_hosts.add(ip)
                        else:
                            # No ignore port specified, add if any port is open
                            live_hosts.add(ip)
        return list(live_hosts)
    except FileNotFoundError:
        print_yellow(f"    Warning: GNMAP file not found for parsing: {gnmap_file}")
        return []
    except Exception as e:
        print_red(f"    Error parsing GNMAP file {gnmap_file}: {e}")
        return []

def parse_gnmap_for_all_open_ports(gnmap_file):
    """Parses a GNMAP file to extract all unique open ports."""
    open_ports = set()
    try:
        with open(gnmap_file, 'r') as f:
            content = f.read() # Read whole file for efficiency with findall
            found_ports = re.findall(r"(\d+)/open/", content)
            open_ports.update(found_ports)
        # Return sorted list of unique ports
        return sorted(list(open_ports), key=int)
    except FileNotFoundError:
        print_yellow(f"    Warning: GNMAP file not found for parsing open ports: {gnmap_file}")
        return []
    except Exception as e:
        print_red(f"    Error parsing GNMAP file {gnmap_file} for open ports: {e}")
        return []

def get_ports_for_ip(ip, gnmap_file):
    """Extracts open ports for a specific IP from a gnmap file. (Reused)"""
    ports = []
    try:
        with open(gnmap_file, 'r') as f:
            for line in f:
                 # Regex accounts for potential () after IP
                if re.match(rf"^Host:\s+{re.escape(ip)}\s*(?:\(\))?\s+.*\s+Ports:\s+", line):
                    found_ports = re.findall(r"(\d+)/open/", line)
                    ports.extend(found_ports)
                    break # Assume only one relevant line per host per file
        return sorted(list(set(ports)), key=int) # Return unique, sorted ports
    except FileNotFoundError:
        return []
    except Exception as e:
        # Print error here as it's specific to this IP lookup
        print_red(f"\nError reading/parsing {gnmap_file} for IP {ip}: {e}")
        return []

def run_deep_scan_worker(ip, scan_title, phase3_gnmap_path, phase1_gnmap_path):
    """Worker function for Phase 4 parallel Nmap scans."""
    output_base = f"{scan_title}_phase4_DeepScan_HOST_{ip}"
    output_nmap_file = f"{output_base}.nmap"
    scan_message_prefix = f"Scan for {ip}:"

    # Check if already scanned
    if os.path.exists(output_nmap_file):
        return f"{scan_message_prefix} Skipped - Output file {output_nmap_file} already exists."

    # Find ports: Check Phase 3 first, then Phase 1 as fallback
    ports = []
    if phase3_gnmap_path and os.path.exists(phase3_gnmap_path):
        ports = get_ports_for_ip(ip, phase3_gnmap_path)

    if not ports and phase1_gnmap_path and os.path.exists(phase1_gnmap_path):
        ports = get_ports_for_ip(ip, phase1_gnmap_path)

    port_string = ",".join(ports)

    if not port_string:
        return f"{scan_message_prefix} Skipped - No open ports found in Phase 3 or Phase 1 GNMAP files."

    # Construct Nmap command for Phase 4
    nmap_command = [
        'nmap', '-A', '-T4',
        '--max-retries', '3',
        '--max-rtt-timeout', '300ms',
        '--host-timeout', '8m',
        '-Pn', # Assume host is up based on previous phases
        '-p', port_string,
        ip,
        '-oA', output_base # Output all formats (Nmap, GNMAP, XML)
    ]

    # Execute Nmap
    try:
        # print_blue(f"[*] Starting deep scan {ip} -p {port_string}") # Can be noisy with progress bar
        result = subprocess.run(nmap_command, capture_output=True, text=True, check=False)

        if result.returncode == 0:
            return f"{scan_message_prefix} Scan Successful (Output: {output_base}.*)"
        else:
            error_details = result.stderr.strip()
            if not error_details and result.stdout.strip():
                 error_details = result.stdout.strip().splitlines()[-1]
            return f"{scan_message_prefix} Scan Failed (Code {result.returncode}). Error: {error_details[:200]}"

    except FileNotFoundError:
        return f"{scan_message_prefix} CRITICAL ERROR: 'nmap' command not found." # Should have been caught earlier
    except Exception as e:
        return f"{scan_message_prefix} Scan Error ({type(e).__name__}: {e})"

def combine_nmap_xml_python(scan_title):
    """Combines Nmap XML output files using xml.etree.ElementTree."""
    output_file = f"{scan_title}_Combined_DeepScan.xml"
    input_pattern = f"{scan_title}_phase4_DeepScan_HOST_*.xml"
    input_files = glob.glob(input_pattern)

    if not input_files:
        print_yellow(f"Warning: No input XML files found matching '{input_pattern}'. Creating empty combined file.")
        # Create a minimal valid empty nmaprun file
        root = ET.Element("nmaprun")
        ET.SubElement(root, "scaninfo", type="unknown", protocol="unknown", numservices="0", services="")
        tree = ET.ElementTree(root)
        try:
            tree.write(output_file, encoding="utf-8", xml_declaration=True)
        except Exception as e:
            print_red(f"Error writing empty combined XML file {output_file}: {e}")
        return False

    print_blue(f"[+] Combining {len(input_files)} Nmap XML files into '{output_file}'")

    # Use the first file to establish the root and attributes
    try:
        first_tree = ET.parse(input_files[0])
        combined_root = first_tree.getroot()
        # Keep scaninfo etc. from the first file, remove its host elements initially
        hosts_to_keep = [] # We'll add all hosts back
    except Exception as e:
        print_red(f"Error parsing first XML file ({input_files[0]}): {e}. Cannot combine.")
        return False

    # Remove initial host elements before adding all back
    for host in combined_root.findall('host'):
         combined_root.remove(host)

    # Iterate through all input files (including the first one again)
    combined_hosts = 0
    skipped_files = 0
    for file in input_files:
        try:
            tree = ET.parse(file)
            root = tree.getroot()
            # Find host elements that are UP
            found_in_file = 0
            for host in root.findall('host'):
                # Check if host status is 'up'
                status = host.find('status')
                if status is not None and status.get('state') == 'up':
                    combined_root.append(host) # Append the <host> element to the combined root
                    found_in_file += 1
            if found_in_file > 0:
                # print(f"    - Added {found_in_file} host(s) from {file}")
                combined_hosts += found_in_file
            else:
                print_yellow(f"    - No 'up' hosts found in {file}")

        except ET.ParseError as e:
            print_red(f"    Warning: Skipping invalid XML file {file}: {e}")
            skipped_files += 1
        except Exception as e:
            print_red(f"    Warning: Skipping file {file} due to error: {e}")
            skipped_files += 1

    # Update runstats if possible (basic example)
    runstats = combined_root.find('runstats')
    if runstats is not None:
        hosts_stats = runstats.find('hosts')
        if hosts_stats is not None:
            hosts_stats.set('up', str(combined_hosts))
            hosts_stats.set('total', str(combined_hosts)) # Or adjust if tracking total processed

    # Write the combined XML tree
    try:
        combined_tree = ET.ElementTree(combined_root)
        combined_tree.write(output_file, encoding="utf-8", xml_declaration=True)
        print_green(f"Successfully combined {combined_hosts} host records into '{output_file}'.")
        if skipped_files > 0:
            print_yellow(f"Skipped {skipped_files} invalid or problematic XML files.")
        return True
    except Exception as e:
        print_red(f"Error writing combined XML file {output_file}: {e}")
        return False


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
    except AttributeError: # Handle non-POSIX systems like Windows
        if os.name != 'posix':
             print_yellow("Warning: Could not check for root privileges on this OS.")
        else:
             print_red("Could not determine user privileges. Exiting.")
             sys.exit(1)

    # --- User Input ---
    scan_title = input("Enter a unique scan title (e.g., ProjectX_Q1_Scan): ")
    host_list_file = input("Enter the path to the host list file: ")
    # Input validation for topPorts
    while True:
        top_ports_str = input("Enter number of --top-ports: ")
        if top_ports_str.isdigit() and int(top_ports_str) > 0:
            top_ports = int(top_ports_str)
            break
        else:
            print_red("Please enter a positive integer for --top-ports.")

    ignore_port = input("Enter a port to exclude (if this port is the only live port, scans will be excluded): ")
    # Validate ignore_port format (optional but good)
    if ignore_port and not ignore_port.isdigit():
        print_yellow(f"Warning: Ignoring invalid 'ignore port' value '{ignore_port}'. No port will be ignored.")
        ignore_port = ""

    # Default value handling for ping sweep
    ping_sweep_q = input("Skip Ping Sweep? (Y/n): ")
    skip_ping_sweep = (ping_sweep_q.lower() or 'y') == 'y' # Default to Yes (skip)

    # Default value handling for Phase 3
    phase3_default = "-p-"
    print(f"Phase 3 does a complete port discovery (default: {phase3_default}).")
    print("You can overwrite that here (e.g., -p 1-1000, --top-ports 1000, skip).")
    phase3_answer = input("Enter Phase 3 port spec or 'skip' [default: uses Phase 1 results]: ")
    if not phase3_answer: # User pressed Enter
        phase3_mode = "skip" # Default to skipping if empty input
        print_yellow("No input for Phase 3, defaulting to 'skip' (using Phase 1 results).")
    elif phase3_answer.lower() == 'skip':
        phase3_mode = "skip"
    else:
        phase3_mode = phase3_answer # Use user's custom spec (e.g., "-p-", "--top-ports 1000")

    # Input validation for parallel scans
    while True:
        how_many_parallel_str = input("How many parallel scans should we run in phase4? ")
        if how_many_parallel_str.isdigit() and int(how_many_parallel_str) > 0:
            how_many_parallel = int(how_many_parallel_str)
            break
        else:
            print_red("Please enter a positive integer for parallel scans.")

    # --- Input Validation ---
    if not scan_title:
      print_red("Error: Scan title cannot be empty.")
      sys.exit(1)
    if not os.path.isfile(host_list_file):
      print_red(f"Error: Host list file '{host_list_file}' not found.")
      sys.exit(1)

    # Define standard filenames
    phase1_base = f"{scan_title}_phase1_Top{top_ports}Ports"
    phase1_gnmap = f"{phase1_base}.gnmap"
    phase2_base = f"{scan_title}_phase2_PingSweep"
    phase2_gnmap = f"{phase2_base}.gnmap"
    phase3_base = f"{scan_title}_phase3_Port_Disco"
    phase3_gnmap = f"{phase3_base}.gnmap"
    live_hosts_temp_file = f"{scan_title}_live_hosts.txt" # Temp file before unique sort
    live_hosts_final_file = f"{scan_title}_live_hosts_final.txt" # Final unique sorted list
    open_ports_file = f"{scan_title}_open_ports.txt"


    clear_screen()
    print_yellow(f"--- Starting Scan: {scan_title} ---")
    print_yellow(f"--- Using Host List: {host_list_file} ---")
    print_yellow(f"--- Top Ports (Phase 1): {top_ports} ---")
    print_yellow(f"--- Ignore Port (if only port): {ignore_port or 'None'} ---")
    print_yellow(f"--- Skip Ping Sweep (Phase 2): {'Yes' if skip_ping_sweep else 'No'} ---")
    print_yellow(f"--- Phase 3 Mode: {phase3_mode} ---")
    print_yellow(f"--- Parallel Scans (Phase 4): {how_many_parallel} ---")
    print("-" * 20)

    # --- Phase 1: Discovery (SYN Scan, Top X, No Ping) ---
    nmap_phase1_args = [
        'nmap', '-sS', '-T4', '--max-retries', '1', '--max-rtt-timeout', '300ms',
        '--host-timeout', '3m', '--max-scan-delay', '5', '--min-rate', '800',
        '-Pn', '-n',
        '-iL', host_list_file,
        '--top-ports', str(top_ports),
        '-oA', phase1_base
    ]
    if not run_nmap_command(nmap_phase1_args, f"Phase 1: Discovery Scan (Top {top_ports} Ports, No Ping)"):
        print_red("Phase 1 failed. Exiting.")
        sys.exit(1)

    # --- Extract Live Hosts (From Phase 1) ---
    print_blue("[+] Extracting Live Hosts found in Phase 1")
    phase1_live_hosts = parse_gnmap_for_live_hosts(phase1_gnmap, ignore_port)
    if phase1_live_hosts:
        print_green(f"    Found {len(phase1_live_hosts)} potential live hosts in Phase 1.")
        try:
            # Overwrite the temp file initially
            with open(live_hosts_temp_file, 'w') as f:
                for ip in sorted(phase1_live_hosts):
                    f.write(ip + '\n')
        except Exception as e:
            print_red(f"    Error writing Phase 1 live hosts to {live_hosts_temp_file}: {e}")
    else:
        print_yellow(f"    No live hosts found in Phase 1 (or all had only ignored port {ignore_port}).")
        # Create empty temp file to avoid errors later if Phase 2 is skipped
        open(live_hosts_temp_file, 'w').close()


    # --- Phase 2: Ping Sweep (Optional) ---
    if not skip_ping_sweep:
        nmap_phase2_args = [
            'nmap', '-sn', '-T4', '--max-retries', '1', '--max-rtt-timeout', '300ms',
            '--host-timeout', '5m', '-n',
            '-iL', host_list_file,
            '-oA', phase2_base
        ]
        if run_nmap_command(nmap_phase2_args, "Phase 2: Ping Sweep on original list"):
            # Extract live hosts from Phase 2 and APPEND to temp file
            print_blue("[+] Extracting Live Hosts found in Phase 2")
            phase2_live_hosts = []
            try:
                 with open(phase2_gnmap, 'r') as f:
                     for line in f:
                         # Simple grep "Host: IP (Hostname) Status: Up"
                         if "Status: Up" in line and line.startswith("Host:"):
                             match = re.match(r"Host:\s+(\S+)", line)
                             if match:
                                 phase2_live_hosts.append(match.group(1))
                 if phase2_live_hosts:
                     print_green(f"    Found {len(phase2_live_hosts)} hosts responding to ping in Phase 2.")
                     try:
                         # Append Phase 2 hosts to the temp file
                         with open(live_hosts_temp_file, 'a') as f:
                             for ip in sorted(list(set(phase2_live_hosts))): # Ensure uniqueness before appending
                                 f.write(ip + '\n')
                     except Exception as e:
                         print_red(f"    Error appending Phase 2 live hosts to {live_hosts_temp_file}: {e}")
                 else:
                     print_yellow("    No hosts responded to ping in Phase 2.")
            except FileNotFoundError:
                 print_yellow(f"    Warning: Phase 2 GNMAP file {phase2_gnmap} not found for parsing.")
            except Exception as e:
                 print_red(f"    Error parsing Phase 2 GNMAP file {phase2_gnmap}: {e}")
    else:
        print_yellow("[+] Skipping Phase 2 Ping Sweep as requested.")

    # --- Consolidate and Finalize Live Hosts ---
    print_blue("[+] Consolidating and saving final list of unique live hosts")
    final_live_hosts = set()
    try:
        if os.path.exists(live_hosts_temp_file):
            with open(live_hosts_temp_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip: # Basic validation: non-empty line
                       # Add more robust IP validation here if needed (e.g., using ipaddress module)
                       final_live_hosts.add(ip)
            # Sort and write to the final file
            sorted_live_hosts = sorted(list(final_live_hosts))
            with open(live_hosts_final_file, 'w') as f:
                 for ip in sorted_live_hosts:
                     f.write(ip + '\n')

            if sorted_live_hosts:
                 print_green(f"[+] Final unique live hosts ({len(sorted_live_hosts)}) saved to {live_hosts_final_file}")
            else:
                 print_red(f"[!] Warning: No live hosts found in total from Phases 1 & 2.")
                 print_red("    Cannot proceed with Phase 3 or 4 without live hosts.")
                 # Optionally clean up temp file: os.remove(live_hosts_temp_file)
                 sys.exit(1) # Exit if no hosts found

            # Clean up the temporary file
            os.remove(live_hosts_temp_file)

        else:
             print_red("[!] Error: Temporary live hosts file not found after Phases 1 & 2.")
             sys.exit(1)

    except Exception as e:
        print_red(f"Error processing live hosts file: {e}")
        sys.exit(1)

    # --- Phase 3: Discover all ports (or skip) ---
    phase3_completed = False
    if phase3_mode == "skip":
        print_blue("[+] Phase 3: Skipping port discovery, using Phase 1 results.")
        try:
            if os.path.exists(phase1_gnmap):
                 shutil.copy2(phase1_gnmap, phase3_gnmap) # Use copy2 to preserve metadata
                 # Append note
                 with open(phase3_gnmap, 'a') as f:
                     f.write("\n# Phase 3 skipped, results copied from Phase 1.\n")
                 print_green(f"    Copied {phase1_gnmap} to {phase3_gnmap}")
                 phase3_completed = True
            else:
                 print_red(f"    Error: Cannot skip Phase 3 because Phase 1 GNMAP file ({phase1_gnmap}) not found!")
                 # Decide if you want to exit or try to proceed without Phase 3 results
                 sys.exit(1)
        except Exception as e:
            print_red(f"    Error copying Phase 1 results for skipped Phase 3: {e}")
            sys.exit(1) # Exit if copy fails
    else:
        # Run Phase 3 Nmap scan using user's port spec
        print_blue(f"[+] Phase 3: Starting Port Discovery Scan on {len(sorted_live_hosts)} Live Hosts ({phase3_mode})")
        nmap_phase3_base_args = [
            'nmap', '-sS', '-Pn', '-n', '-T4', '--max-retries', '2',
            '--max-rtt-timeout', '300ms', '--host-timeout', '15m',
            '--max-scan-delay', '5', '--min-rate', '800',
            '-iL', live_hosts_final_file
            # Add port spec based on phase3_mode
        ]
        # Split user input like "-p 1-100,--top-ports 10" correctly for subprocess
        if phase3_mode.startswith('-p') or phase3_mode.startswith('--'):
             # Handle simple cases like '-p-' or '--top-ports 100'
             # More complex splitting might be needed for combined args
             parts = phase3_mode.split(maxsplit=1)
             nmap_phase3_base_args.extend(parts)
        else:
             print_red(f"    Warning: Unrecognized Phase 3 port spec format '{phase3_mode}'. Using default '-p-'.")
             nmap_phase3_base_args.append('-p-') # Fallback to all ports

        nmap_phase3_base_args.extend(['-oA', phase3_base])

        if run_nmap_command(nmap_phase3_base_args, f"Phase 3: Port Discovery Scan ({phase3_mode})"):
             phase3_completed = True
        else:
             print_red("    Phase 3 Nmap scan failed. Will attempt Phase 4 using Phase 1 ports if available.")
             # No exit here, Phase 4 logic will handle fallback

    # --- Extract Open Ports (From Phase 3 Results if available) ---
    if phase3_completed:
        print_blue("[+] Extracting All Unique Open Ports discovered")
        all_open_ports = parse_gnmap_for_all_open_ports(phase3_gnmap)
        if all_open_ports:
            print_green(f"    Found {len(all_open_ports)} unique open ports across all scanned hosts.")
            open_ports_str = ",".join(map(str, all_open_ports)) # Join with commas
            try:
                with open(open_ports_file, 'w') as f:
                    f.write(open_ports_str + '\n') # Write comma-separated string
                print_green(f"    All open ports saved (comma-separated) to {open_ports_file}")
            except Exception as e:
                 print_red(f"    Error writing open ports list to {open_ports_file}: {e}")
        else:
            print_yellow(f"    Warning: No open ports found in {phase3_gnmap}.")
            # Create empty file? Or just note that it's empty.
            open(open_ports_file, 'w').close()
    else:
         print_yellow("[+] Skipping extraction of open ports as Phase 3 did not complete successfully or was skipped.")
         # Ensure the open ports file is empty if Phase 3 failed/skipped and Phase 1 ports are used as fallback in Phase 4
         open(open_ports_file, 'w').close()


    # --- Phase 4: Deep Scan (Parallel) ---
    print_blue(f"\n[+] Phase 4: Starting Deep Scan on {len(sorted_live_hosts)} Live Hosts (Parallelism: {how_many_parallel})")
    if not sorted_live_hosts:
         print_red("    Cannot start Phase 4: No live hosts identified.")
    else:
         tasks = []
         results = []
         completed_count = 0
         total_tasks = len(sorted_live_hosts)

         # Determine phase 1 gnmap path for fallback
         phase1_gnmap_for_p4 = phase1_gnmap if os.path.exists(phase1_gnmap) else None
         phase3_gnmap_for_p4 = phase3_gnmap if os.path.exists(phase3_gnmap) else None # Check existence


         with ProcessPoolExecutor(max_workers=how_many_parallel) as executor:
             print_blue(f"    Submitting {total_tasks} deep scan jobs...")
             # Submit tasks
             for ip in sorted_live_hosts:
                  # Pass necessary paths to the worker
                  future = executor.submit(run_deep_scan_worker, ip, scan_title, phase3_gnmap_for_p4, phase1_gnmap_for_p4)
                  tasks.append(future)

             print_blue("    Waiting for scans to complete...")
             if total_tasks > 0:
                 print(f"\r    Progress: 0.0% (0/{total_tasks})", end='', flush=True)

             # Process results as they complete
             for future in as_completed(tasks):
                 completed_count += 1
                 percentage = (completed_count / total_tasks) * 100 if total_tasks > 0 else 100
                 progress_string = f"Progress: {percentage:.1f}% ({completed_count}/{total_tasks})"

                 try:
                     result_message = future.result()
                     results.append(result_message)
                     # Print progress update
                     print(f"\r    {progress_string:<60}", end='', flush=True)

                     # Print errors/skips on new lines
                     if "Failed" in result_message or "Error" in result_message:
                         print()
                         print_red(f"    {result_message}")
                         print(f"\r    {progress_string:<60}", end='', flush=True) # Reprint progress
                     elif "Skipped - Output file" in result_message:
                          print()
                          print_purple(f"    {result_message}")
                          print(f"\r    {progress_string:<60}", end='', flush=True) # Reprint progress
                     elif "Skipped - No open ports" in result_message:
                          print()
                          print_yellow(f"    {result_message}")
                          print(f"\r    {progress_string:<60}", end='', flush=True) # Reprint progress


                 except Exception as exc:
                     # Handle exceptions from the future/worker process itself
                     completed_count += 1 # Still counts as completed task, albeit failed
                     percentage = (completed_count / total_tasks) * 100 if total_tasks > 0 else 100
                     progress_string = f"Progress: {percentage:.1f}% ({completed_count}/{total_tasks})"
                     print()
                     print_red(f'\n    CRITICAL TASK FAILURE (IP processing might have crashed): {exc}')
                     results.append(f"Task Error: {exc}")
                     print(f"\r    {progress_string:<60}", end='', flush=True)

             print() # Final newline after loop finishes
             print_green("[+] Phase 4 Deep Scan complete.")


    # --- Combine XML Results (Optional) ---
    print_blue("\n[+] Attempting to Combine Phase 4 XML Results")
    combine_nmap_xml_python(scan_title)
    print_yellow("\nReminder: For advanced analysis, consider dedicated tools like 'nmap-to-sqlite'.")
    # Example: print_yellow("# for file in *.xml; do python3 nmap-to-sqlite.py \"$file\"; done")

    print_blue(f"\n--- Scan {scan_title} Complete ---")
