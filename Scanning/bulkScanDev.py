#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
import re
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
# Removed: import xml.etree.ElementTree as ET
import logging
import shlex # For safe command string splitting

try:
    from colorama import init, Fore, Style
    init(autoreset=True) # Auto-reset color after each print
except ImportError:
    print("Warning: colorama library not found. Colors will not be displayed.")
    print("Install it using: pip install colorama")
    # Define dummy Fore and Style objects if colorama is not available
    class DummyStyle:
        def __getattr__(self, name):
            return ""
    Fore = DummyStyle()
    Style = DummyStyle()

# --- Logging Setup ---
# Keep logging basic unless verbose flag is used during argument parsing
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# --- Color Print Functions ---
def print_color(color, text):
    print(f"{color}{text}{Style.RESET_ALL}")

def print_green(text): print_color(Fore.GREEN, text)
def print_yellow(text): print_color(Fore.YELLOW, text)
def print_red(text): print_color(Fore.RED, text)
def print_blue(text): print_color(Fore.BLUE, text)
def print_purple(text): print_color(Fore.MAGENTA, text) # Magenta is often used for Purple


# --- Helper Function for Prompts with Defaults ---
def prompt_user(prompt_text, default=None, validation_func=None, error_msg="Invalid input."):
    """Prompts the user for input, showing default, and optionally validating."""
    prompt_suffix = f" [{default}]" if default is not None else ""
    while True:
        user_input = input(f"{prompt_text}{prompt_suffix}: ").strip()
        if not user_input and default is not None:
            value = default
            print(f"Using default: {value}") # Show that default is used
            break
        elif user_input:
            value = user_input
            if validation_func:
                if validation_func(value):
                    break # Valid input
                else:
                    print_red(error_msg)
            else:
                break # No validation needed
        elif default is None: # Required input, no default provided
             print_red("This field cannot be empty.")
        # If input is empty AND default is None, loop continues asking

    # Attempt to convert numeric defaults/inputs if possible (e.g., for ports, parallel scans)
    if isinstance(default, int):
        try:
            return int(value)
        except ValueError:
             print_red(f"Expected an integer, but received '{value}'. Using default '{default}'.")
             return default # Fallback to default if conversion fails after prompt
    elif isinstance(default, str) and default.isdigit():
         # Handle cases where default might be '1000' (string) but want int
         try:
             return int(value)
         except ValueError:
             # Keep as string if user input wasn't purely numeric
             return value
    return value # Return as string otherwise


# --- Validation Functions ---
def is_valid_path(path_str):
    return Path(path_str).is_file()

def is_not_empty(value):
    return bool(value)

def is_positive_int(value):
    try:
        return int(value) > 0
    except ValueError:
        return False

def is_valid_phase3(value):
    # Basic check - allows 'skip', '-p-', '--top-ports X', etc.
    # More complex validation could be added here if needed.
    return bool(value)

def is_yes_no(value):
     return value.lower() in ['y', 'n', 'yes', 'no']

# --- Core Nmap Functions (run_command, parse_gnmap_*, run_deep_scan) ---
# combine_nmap_xml has been removed.
def run_command(cmd_list, cwd=None, check=True):
    """Runs a command using subprocess and logs output."""
    cmd_str = shlex.join(cmd_list) # For logging
    log.info(f"Running command: {cmd_str}")
    try:
        # Using Popen for potentially long-running nmap, stream output
        process = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd)
        stdout, stderr = process.communicate() # Wait for completion

        if stdout:
            log.debug(f"Command stdout:\n{stdout.strip()}")
        if stderr:
            # Only log stderr as warning if return code is non-zero or if verbose
            if process.returncode != 0 or log.level == logging.DEBUG:
                 log.warning(f"Command stderr:\n{stderr.strip()}")

        if check and process.returncode != 0:
            log.error(f"Command failed with exit code {process.returncode}: {cmd_str}")
            # Include stderr in the exception message for clarity
            error_details = f"Stderr:\n{stderr.strip()}" if stderr.strip() else "No stderr."
            raise subprocess.CalledProcessError(process.returncode, cmd_list, output=stdout, stderr=error_details)
        log.info(f"Command finished successfully: {cmd_str}")
        return stdout, stderr
    except FileNotFoundError:
        log.error(f"Error: Command not found: {cmd_list[0]}")
        raise
    except Exception as e:
        log.error(f"An error occurred while running command '{cmd_str}': {e}")
        raise

def parse_gnmap_live_hosts(gnmap_content, ignore_port=None):
    """Parses .gnmap content to find live hosts with open ports."""
    live_hosts = set()
    host_pattern = re.compile(r"^Host:\s+([\d.]+)\s+\(.*?\)?" # Optional hostname
                             r"\s+Status:\s+Up"
                             r".*?Ports:\s+(.*)", re.MULTILINE)
    port_pattern = re.compile(r"(\d+)/open")

    for match in host_pattern.finditer(gnmap_content):
        ip = match.group(1)
        ports_str = match.group(2)
        open_ports_found = port_pattern.findall(ports_str)

        if open_ports_found:
            if ignore_port is not None: # Check if ignore_port is provided (could be 0)
                # Convert ignore_port to string for comparison
                ignore_port_str = str(ignore_port)
                if all(p == ignore_port_str for p in open_ports_found):
                    log.info(f"Host {ip} only has ignored port {ignore_port} open. Excluding.")
                    continue
            live_hosts.add(ip)

    # Find hosts marked as Up (handles simple -sn output lines where Ports might not exist)
    up_host_pattern = re.compile(r"^Host:\s+([\d.]+)\s+\(.*?\)?"
                                 r"\s+Status:\s+Up", re.MULTILINE)
    for match in up_host_pattern.finditer(gnmap_content):
         ip = match.group(1)
         # Add only if status is up, regardless of ports section existence (for -sn)
         live_hosts.add(ip)

    return live_hosts


def parse_gnmap_open_ports_for_host(gnmap_content, target_ip):
    """Parses .gnmap to find open ports for a specific host."""
    ports = set()
    # Corrected Regex: Looks for the line starting with the Host IP
    # and containing the 'Ports:' section, regardless of 'Status: Up'
    # on that particular line.
    host_line_pattern = re.compile(
        # Match start of line, Host:, the specific IP, optional hostname
        r"^Host:\s+" + re.escape(target_ip) + r"\s+\(.*?\)?"
        # Match any characters non-greedily until the Ports section
        r".*?\sPorts:\s+"
        # Capture the rest of the line (the port details)
        r"(.*)",
        re.MULTILINE
    )
    port_pattern = re.compile(r"(\d+)/open") # Extracts port number if '/open'

    # Search the entire gnmap content for the pattern
    match = host_line_pattern.search(gnmap_content)
    if match:
        ports_str = match.group(1) # Get the captured port details string
        log.debug(f"Found ports string for {target_ip}: {ports_str[:100]}...") # Log found string
        found_ports = port_pattern.findall(ports_str) # Find all 'NNN/open'
        ports.update(found_ports)
        log.debug(f"Extracted open ports for {target_ip}: {ports}")
    else:
         log.warning(f"Regex did not find a 'Ports:' line for host {target_ip} in the provided gnmap content.")


    # Return sorted list of integers
    return sorted([int(p) for p in ports])


def parse_gnmap_all_open_ports(gnmap_content):
    """Parses .gnmap to find all unique open ports across all hosts."""
    port_pattern = re.compile(r"(\d+)/open")
    ports = set(port_pattern.findall(gnmap_content))
    # Return sorted list of integers
    return sorted([int(p) for p in ports])


def run_deep_scan(ip, scan_title_dir, phase3_gnmap_path, phase1_gnmap_path):
    """Task for running the Phase 4 deep scan on a single IP."""
    output_prefix = scan_title_dir / f"phase4_DeepScan_HOST_{ip}"
    xml_file = output_prefix.with_suffix(".xml") # Still track XML file for skipping logic

    if xml_file.exists():
        print_purple(f"[*] Skipping deep scan for {ip}: Output file {xml_file.name} already exists.")
        return ip, True # Indicate skipped

    ports_to_scan = []
    phase3_content = ""
    phase1_content = ""

    try:
        # Read content only if files exist
        if phase3_gnmap_path.exists():
            phase3_content = phase3_gnmap_path.read_text()
            ports_to_scan = parse_gnmap_open_ports_for_host(phase3_content, ip)

        if not ports_to_scan and phase1_gnmap_path.exists():
            log.info(f"No open ports found for {ip} in Phase 3 results, checking Phase 1...")
            phase1_content = phase1_gnmap_path.read_text()
            ports_to_scan = parse_gnmap_open_ports_for_host(phase1_content, ip)

        if not ports_to_scan:
            print_red(f"[!] No open ports found for {ip} in Phase 1 or 3 results. Skipping Deep Scan.")
            return ip, False # Indicate failure/nothing to do

        port_str = ",".join(map(str, ports_to_scan))
        print_blue(f"[*] Starting deep scan on {ip} for ports: {port_str}")

        nmap_cmd = [
            "nmap", "-A", "-T4",
            "--max-retries", "3",
            "--max-rtt-timeout", "300ms",
            "--host-timeout", "8m",
            "-Pn",
            "-p", port_str,
            ip,
            "-oA", str(output_prefix)
        ]
        run_command(nmap_cmd, cwd=scan_title_dir) # Run in the scan directory
        print_green(f"[+] Deep scan completed for {ip}")
        return ip, True

    except FileNotFoundError:
         log.error("nmap command not found. Make sure nmap is installed and in your PATH.")
         # Re-raise or handle appropriately - maybe return False?
         return ip, False
    except subprocess.CalledProcessError as e:
        print_red(f"[!] Deep scan failed for {ip}. Error: {e}")
        # Log the specific error details from CalledProcessError
        log.error(f"Deep scan command failed for {ip}. Return code: {e.returncode}\nStderr: {e.stderr}")
        return ip, False
    except Exception as e:
        print_red(f"[!] Unexpected error during deep scan for {ip}: {e}")
        log.exception(f"Deep scan error for {ip}")
        return ip, False

# --- Removed combine_nmap_xml Function ---
# The entire combine_nmap_xml function definition was removed from here.

# --- Main Execution ---
def main():
    # --- Argument Parser ---
    parser = argparse.ArgumentParser(
        description="Perform a multi-phase network scan using nmap, with interactive prompts for missing arguments.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Shows defaults in help
    )
    # Changed required positional args to optional flags
    parser.add_argument("-s", "--scan-title", help="A unique name for this scan.")
    parser.add_argument("-L", "--host-list", help="Path to the file containing target IPs.")

    # Optional args with defaults
    parser.add_argument("-t", "--top-ports", type=int, default=1000, help="Number of top ports for Phase 1.")
    parser.add_argument("-i", "--ignore-port", type=int, default=None, metavar='PORT', help="Ignore hosts in Phase 1 if this is the only open port.")
    parser.add_argument("--skip-ping-sweep", action="store_true", help="Skip the Phase 2 ping sweep.") # Boolean flag
    parser.add_argument("--phase3", default="-p-",
                        help="Phase 3 port spec ('-p-', '--top-ports X', 'skip', etc.).")
    parser.add_argument("-j", "--parallel-scans", type=int, default=35, help="Number of parallel deep scans (Phase 4).")
    parser.add_argument("-o", "--output-dir", default=".", help="Parent directory for scan results.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")

    args = parser.parse_args()

    # --- Configure Logging Level ---
    if args.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO) # Show INFO level messages even if not verbose

    # --- Root Check ---
    if os.geteuid() != 0:
        print_red("Error: This script requires root privileges to run SYN scans (-sS).")
        sys.exit(1)

    # --- Interactive Prompts (if args missing) ---
    print_blue("--- Scan Configuration ---")

    # Scan Title (Required)
    if args.scan_title is None:
        args.scan_title = prompt_user(
            "Enter a unique scan title (e.g., ProjectX_Q1_Scan)",
            validation_func=is_not_empty,
            error_msg="Scan title cannot be empty."
        )
    else:
         print(f"Using Scan Title from argument: {args.scan_title}")


    # Host List File (Required)
    if args.host_list is None:
        args.host_list = prompt_user(
            "Enter the path to the host list file",
            validation_func=is_valid_path,
            error_msg="Host list file not found or is not a file."
        )
    else:
         # Validate the provided argument path as well
         if not is_valid_path(args.host_list):
              print_red(f"Error: Host list file from argument not found: {args.host_list}")
              # Prompt user again if argument path is invalid
              args.host_list = prompt_user(
                    "Re-enter the path to the host list file",
                    validation_func=is_valid_path,
                    error_msg="Host list file not found or is not a file."
                )
         else:
              print(f"Using Host List from argument: {args.host_list}")

    # Convert host_list to Path object after getting/validating it
    host_file = Path(args.host_list)

    # Top Ports (Optional with default)
    args.top_ports = prompt_user(
        f"Enter number of --top-ports for Phase 1",
        default=args.top_ports, # Use default from argparse
        validation_func=is_positive_int,
        error_msg="Please enter a positive integer for top ports."
    )

    # Ignore Port (Optional, can be None)
    # Need careful handling as default is None
    ignore_port_input = input(f"Enter a port to exclude (leave blank for none) [{args.ignore_port if args.ignore_port is not None else 'None'}]: ").strip()
    if ignore_port_input:
        try:
            args.ignore_port = int(ignore_port_input)
            if args.ignore_port < 1 or args.ignore_port > 65535:
                 print_red("Invalid port number. Ignoring exclusion.")
                 args.ignore_port = None
        except ValueError:
            print_red("Invalid input for ignore port. Ignoring exclusion.")
            args.ignore_port = None
    # If input was blank, args.ignore_port keeps its original value (None from argparse default)

    # Ping Sweep (Boolean)
    # Default is False unless --skip-ping-sweep is given
    ping_sweep_prompt_default = 'N' if not args.skip_ping_sweep else 'Y'
    skip_ping_input = prompt_user(
        "Skip Ping Sweep? (Y/n)",
        default=ping_sweep_prompt_default,
        validation_func=is_yes_no,
        error_msg="Please enter Y or N."
    )
    args.skip_ping_sweep = skip_ping_input.lower().startswith('y')


    # Phase 3 Options (Optional with default)
    print(f"Phase 3 defines port discovery on live hosts.")
    print(f"Options: '-p-' (all), '--top-ports X', 'T:1-65535', 'skip' (use Phase 1).")
    print_yellow("Warning: '-p-' can be very slow. 'skip' or '--top-ports' recommended.")
    args.phase3 = prompt_user(
        f"Enter Phase 3 port specification",
        default=args.phase3, # Use default from argparse
        validation_func=is_valid_phase3, # Basic check
        error_msg="Phase 3 specification cannot be empty (use 'skip' if intended)."
    )

    # Parallel Scans (Optional with default)
    args.parallel_scans = prompt_user(
        f"How many parallel scans should run in Phase 4?",
        default=args.parallel_scans, # Use default from argparse
        validation_func=is_positive_int,
        error_msg="Please enter a positive integer for parallel scans."
    )

    # Output Directory (uses argparse default if not prompted/overridden)
    # You could add a prompt here too if desired, similar to others.
    print(f"Output directory base: {args.output_dir}")

    # --- Setup Output Directory ---
    base_output_dir = Path(args.output_dir)
    # Use the potentially updated scan_title from prompt/args
    scan_title_dir = base_output_dir / args.scan_title
    try:
        scan_title_dir.mkdir(parents=True, exist_ok=True)
        log.info(f"Ensured output directory exists: {scan_title_dir.resolve()}")
    except OSError as e:
        print_red(f"Error creating output directory {scan_title_dir}: {e}")
        sys.exit(1)

    # --- Change Directory and Start Scan ---
    original_cwd = Path.cwd()
    try: # Use try/finally to ensure we change back
        os.chdir(scan_title_dir)
        current_scan_dir = Path(".") # Use relative path now

        print_yellow(f"\n--- Starting Scan: {args.scan_title} ---")
        print_yellow(f"--- Using Host List: {host_file.resolve()} ---")
        print_yellow(f"--- Output Directory: {current_scan_dir.resolve()} ---")
        # Print other confirmed settings
        print_yellow(f"--- Phase 1 Top Ports: {args.top_ports} ---")
        print_yellow(f"--- Ignore Port (Phase 1): {args.ignore_port if args.ignore_port is not None else 'None'} ---")
        print_yellow(f"--- Skip Ping Sweep: {'Yes' if args.skip_ping_sweep else 'No'} ---")
        print_yellow(f"--- Phase 3 Spec: {args.phase3} ---")
        print_yellow(f"--- Phase 4 Parallel Scans: {args.parallel_scans} ---")

        # Define file paths relative to current_scan_dir (which is scan_title_dir)
        phase1_output_prefix = f"{args.scan_title}_phase1_Top{args.top_ports}Ports"
        phase1_gnmap_path = current_scan_dir / f"{phase1_output_prefix}.gnmap"

        phase2_output_prefix = f"{args.scan_title}_phase2_PingSweep"
        phase2_gnmap_path = current_scan_dir / f"{phase2_output_prefix}.gnmap"

        phase3_output_prefix = f"{args.scan_title}_phase3_Port_Disco"
        phase3_gnmap_path = current_scan_dir / f"{phase3_output_prefix}.gnmap"

        live_hosts_file = current_scan_dir / f"{args.scan_title}_live_hosts.txt"
        open_ports_file = current_scan_dir / f"{args.scan_title}_open_ports.txt"

        # --- Phase 1: Discovery ---
        print_blue(f"\n[+] Phase 1: Discovery Scan (Top {args.top_ports} Ports, No Ping)")
        phase1_cmd = [
            "nmap", "-sS", "-T4",
            "--max-retries", "1", "--max-rtt-timeout", "300ms", "--host-timeout", "3m",
            "--max-scan-delay", "5", "--min-rate", "800",
            "-Pn", "-n",
            "-iL", str(host_file.resolve()), # Absolute path to input list
            "--top-ports", str(args.top_ports),
            "-oA", phase1_output_prefix # Output relative to current dir
        ]
        try:
            run_command(phase1_cmd)
            print_green("[+] Phase 1 completed.")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print_red(f"[!] Phase 1 failed: {e}")
            sys.exit(1) # Exit if initial discovery fails

        # --- Phase 2: Ping Sweep ---
        phase2_hosts = set()
        if not args.skip_ping_sweep:
            print_blue("[+] Phase 2: Ping Sweep on original list")
            phase2_cmd = [
                "nmap", "-sn", "-T4",
                "--max-retries", "1", "--max-rtt-timeout", "300ms", "--host-timeout", "5m",
                "-n",
                "-iL", str(host_file.resolve()),
                "-oA", phase2_output_prefix
            ]
            try:
                run_command(phase2_cmd)
                if phase2_gnmap_path.exists():
                     phase2_content = phase2_gnmap_path.read_text()
                     phase2_hosts = parse_gnmap_live_hosts(phase2_content) # No ignore port here
                     print_green(f"[+] Phase 2 completed. Found {len(phase2_hosts)} hosts responding.")
                else:
                    print_yellow("[!] Phase 2 .gnmap file not found after scan.")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print_red(f"[!] Phase 2 failed: {e}")
                # Decide whether to continue or exit
        else:
            print_yellow("[+] Skipping Phase 2 Ping Sweep.")

        # --- Extract Live Hosts ---
        print_blue("[+] Extracting Live Hosts found in Phases 1 & 2")
        phase1_hosts = set()
        if phase1_gnmap_path.exists():
            try:
                phase1_content = phase1_gnmap_path.read_text()
                phase1_hosts = parse_gnmap_live_hosts(phase1_content, args.ignore_port) # Apply ignore port
            except Exception as e:
                print_red(f"[!] Error parsing Phase 1 gnmap file: {e}")
        else:
            print_red("[!] Phase 1 gnmap file not found. Cannot extract live hosts from Phase 1.")

        live_hosts = sorted(list(phase1_hosts.union(phase2_hosts)))

        if live_hosts:
            try:
                with open(live_hosts_file, "w") as f:
                    for host in live_hosts:
                        f.write(host + "\n")
                print_green(f"[+] {len(live_hosts)} Live hosts saved to {live_hosts_file.name}")
            except IOError as e:
                print_red(f"Error writing live hosts file {live_hosts_file.name}: {e}")
        else:
            print_red("[!] Warning: No live hosts found meeting criteria. Further scans may be skipped.")

        # --- Phase 3: Port Discovery ---
        phase3_completed = False
        if not live_hosts:
            print_red("[!] Skipping Phase 3: No live hosts found.")
        elif args.phase3.lower() == 'skip':
            print_blue("[+] Phase 3: Skipped. Using Phase 1 results for port discovery.")
            try:
                if phase1_gnmap_path.exists():
                    shutil.copy(phase1_gnmap_path, phase3_gnmap_path)
                    with open(phase3_gnmap_path, "a") as f:
                        f.write("\n# Copied from Phase 1 due to Phase 3 skip.\n")
                    phase3_completed = True
                    print_green(f"[+] Copied {phase1_gnmap_path.name} to {phase3_gnmap_path.name}")
                else:
                     print_red("[!] Cannot skip Phase 3: Phase 1 gnmap file does not exist.")
            except OSError as e:
                print_red(f"Error copying Phase 1 results for Phase 3 skip: {e}")
        else:
            print_blue(f"[+] Phase 3: Port Discovery Scan ({args.phase3}) on {len(live_hosts)} Live Hosts")
            # Use shlex to handle potential spaces in user-provided phase3 options like "--top-ports 100"
            try:
                 phase3_nmap_opts = shlex.split(args.phase3)
            except ValueError as e:
                 print_red(f"Error parsing Phase 3 options '{args.phase3}': {e}. Defaulting to '-p-'.")
                 phase3_nmap_opts = ["-p-"]


            phase3_cmd = [
                "nmap", "-sS", "-Pn", "-n", "-T4",
                "--max-retries", "2", "--max-rtt-timeout", "500ms", # Slightly increased timeout
                "--host-timeout", "15m",
                "--max-scan-delay", "5", "--min-rate", "800",
                "-iL", str(live_hosts_file.resolve()), # Use absolute path
            ]
            phase3_cmd.extend(phase3_nmap_opts) # Add parsed port spec
            phase3_cmd.extend(["-oA", phase3_output_prefix])

            try:
                run_command(phase3_cmd)
                phase3_completed = True
                print_green("[+] Phase 3 completed.")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print_red(f"[!] Phase 3 failed: {e}")

        # --- Extract Open Ports ---
        open_ports_list = []
        gnmap_for_port_extraction = None
        if phase3_completed and phase3_gnmap_path.exists():
            print_blue("[+] Extracting Open Ports discovered in Phase 3")
            gnmap_for_port_extraction = phase3_gnmap_path
        elif phase1_gnmap_path.exists():
             # Fallback if phase 3 skipped or failed but phase 1 exists
             print_yellow("[!] Phase 3 skipped or failed, extracting overall ports from Phase 1.")
             gnmap_for_port_extraction = phase1_gnmap_path
        else:
            print_red("[!] No usable .gnmap file found from Phase 1 or 3 to extract overall ports.")


        if gnmap_for_port_extraction:
            try:
                content = gnmap_for_port_extraction.read_text()
                open_ports_list = parse_gnmap_all_open_ports(content)
            except Exception as e:
                print_red(f"[!] Error parsing {gnmap_for_port_extraction.name}: {e}")

        if open_ports_list:
            try:
                port_str = ",".join(map(str, open_ports_list))
                open_ports_file.write_text(port_str + "\n")
                print_green(f"[+] All unique open ports ({len(open_ports_list)}) found saved to {open_ports_file.name}")
            except IOError as e:
                print_red(f"Error writing open ports file {open_ports_file.name}: {e}")
        else:
            print_red("[!] Warning: No open ports found in Phase 1 or 3 scan results.")


        # --- Phase 4: Deep Scan ---
        if not live_hosts:
            print_red("[!] Skipping Phase 4: No live hosts found.")
        else:
            print_blue(f"\n[+] Phase 4: Starting Deep Scan on {len(live_hosts)} Live Hosts (using {args.parallel_scans} parallel threads)")

            scan_func = partial(run_deep_scan,
                                scan_title_dir=current_scan_dir,
                                phase3_gnmap_path=phase3_gnmap_path,
                                phase1_gnmap_path=phase1_gnmap_path)

            successful_scans = 0
            failed_scans = 0
            with ThreadPoolExecutor(max_workers=args.parallel_scans) as executor:
                futures = {executor.submit(scan_func, ip): ip for ip in live_hosts}
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        target_ip, result = future.result()
                        if result: # True means success or skipped-existing
                            successful_scans += 1
                        else: # False means failed or skipped-no-ports
                            failed_scans += 1
                    except Exception as exc:
                        print_red(f'[!] Host {ip} generated an exception during Phase 4 future processing: {exc}')
                        log.exception(f"Phase 4 future exception for {ip}")
                        failed_scans += 1

            print_green(f"[+] Phase 4 complete. Successful/Skipped: {successful_scans}, Failures/No Ports: {failed_scans}")

            # --- Removed Combine Phase 4 XML ---
            # The call to combine_nmap_xml was removed from here.
            # The individual phase4_DeepScan_HOST_*.xml files will still exist,
            # but they will not be combined into a single file by this script.

        # --- Final Output ---
        print_blue(f"\n--- Scan {args.scan_title} Complete ---")
        print_blue(f"--- Results are in: {current_scan_dir.resolve()} ---")

    finally:
        # Ensure we change back to the original directory
        os.chdir(original_cwd)
        log.info(f"Changed back to original directory: {original_cwd}")


if __name__ == "__main__":
    main()
