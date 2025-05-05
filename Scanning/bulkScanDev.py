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
import logging
import shlex
import time

try:
    from colorama import init, Fore, Style
    init(autoreset=True) # Auto-reset color after each print
except ImportError:
    print("Warning: colorama library not found. Colors will not be displayed.")
    print("Install it using: pip install colorama")
    # Define dummy Fore and Style objects if colorama is not available
    class DummyColor:
        def __getattr__(self, name):
            return ""
    Fore = DummyColor()
    Style = DummyColor()

log = None  

# --- Color Print Functions ---
# (Using functions similar to the first script)
def print_color(color, text):
    print(f"{color}{text}{Style.RESET_ALL}", flush=True) # Add flush=True

def print_green(text): print_color(Fore.GREEN, text)
def print_yellow(text): print_color(Fore.YELLOW, text)
def print_red(text): print_color(Fore.RED, text)
def print_blue(text): print_color(Fore.BLUE, text)
def print_purple(text): print_color(Fore.MAGENTA, text) # Magenta is often used for Purple

# --- Helper Function for Prompts with Defaults ---
# (Reusing the same function as before)
def prompt_user(prompt_text, default=None, validation_func=None, error_msg="Invalid input."):
    """Prompts the user for input, showing default, and optionally validating."""
    prompt_suffix = f" [{default}]" if default is not None else ""
    while True:
        user_input = input(f"{Style.BRIGHT}{prompt_text}{Style.RESET_ALL}{prompt_suffix}: ").strip()
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
# (Reusing the same functions as before)
def is_valid_path(path_str):
    p = Path(path_str)
    return p.is_file() and os.access(p, os.R_OK) # Also check read permissions

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

# --- Core Nmap Functions (run_command, parse_gnmap_*) ---
def run_command(cmd_list, cwd=None, check=True, description="Running command"):
    """Runs a command using subprocess, logs output, and uses color."""
    cmd_str = shlex.join(cmd_list) # For logging/display
    print_blue(f"[+] {description}")
    print_yellow(f"    Command: {cmd_str}")
    log.info(f"Running command: {cmd_str} in {cwd or Path.cwd()}")
    try:
        # Use Popen for better handling of potential long-running processes if needed
        process = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd)
        stdout, stderr = process.communicate() # Wait for completion

        if stdout:
            log.debug(f"Command stdout:\n{stdout.strip()}")
        if stderr:
            # Log stderr as warning/error based on return code
            if process.returncode != 0:
                log.error(f"Command stderr:\n{stderr.strip()}")
            else:
                log.warning(f"Command stderr (Return Code 0):\n{stderr.strip()}") # Still useful sometimes

        if check and process.returncode != 0:
            log.error(f"Command failed with exit code {process.returncode}: {cmd_str}")
            error_details = f"Stderr:\n{stderr.strip()}" if stderr.strip() else "No stderr."
            # Raise exception but also print red message
            print_red(f"    Command failed (Code: {process.returncode}). Check logs.")
            raise subprocess.CalledProcessError(process.returncode, cmd_list, output=stdout, stderr=error_details)

        print_green(f"    Command completed successfully.")
        log.info(f"Command finished successfully: {cmd_str}")
        return stdout, stderr # Return output streams for potential parsing

    except FileNotFoundError:
        log.error(f"Error: Command not found: {cmd_list[0]}")
        print_red(f"    Error: Command not found: {cmd_list[0]}. Is nmap installed and in PATH?")
        raise
    except Exception as e:
        log.exception(f"An unexpected error occurred while running command '{cmd_str}'")
        print_red(f"    An unexpected error occurred: {e}")
        raise

def parse_gnmap_live_hosts(gnmap_content):
    """
    Parses .gnmap content to find hosts marked as 'Up'.
    Includes hosts even if no open ports are listed in the Ports section.
    """
    live_hosts = set()
    # Pattern to find hosts marked as Up, works for -sS and -sn output
    # Handles optional hostname in parentheses
    up_host_pattern = re.compile(r"^Host:\s+([\d.:a-fA-F]+)\s+(?:\(.*\)\s+)?Status:\s+Up", re.MULTILINE)

    for match in up_host_pattern.finditer(gnmap_content):
         ip = match.group(1)
         live_hosts.add(ip)
         log.debug(f"Found Up host: {ip}")

    log.info(f"Parsed gnmap content. Found {len(live_hosts)} hosts marked 'Up'.")
    return live_hosts

# Renamed from parse_gnmap_open_ports_for_host for clarity
def parse_gnmap_ports_for_host(gnmap_content, target_ip):
    """Parses .gnmap content to find open or open|filtered ports for a specific host."""
    ports = set()
    # Corrected Regex: Looks for the line starting with the Host IP
    # Handles optional hostname, searches until 'Ports:'
    host_line_pattern = re.compile(
        # Match start of line, Host:, the specific IP (IPv4/v6 safe), optional hostname
        r"^Host:\s+" + re.escape(target_ip) + r"\s*(?:\(.*\)\s*)?"
        # Match any characters non-greedily until the Ports section
        r".*?\sPorts:\s+"
        # Capture the rest of the line (the port details)
        r"(.*)",
        re.MULTILINE
    )
    # Pattern to find ports marked as 'open' or 'open|filtered'
    port_pattern = re.compile(r"(\d+)/(?:open|open\|filtered)")

    # Search the entire gnmap content for the pattern
    match = host_line_pattern.search(gnmap_content)
    if match:
        ports_str = match.group(1) # Get the captured port details string
        log.debug(f"Found ports string for {target_ip}: {ports_str[:100]}...") # Log found string
        found_ports = port_pattern.findall(ports_str) # Find all matching ports
        ports.update(found_ports)
        log.debug(f"Extracted open/open|filtered ports for {target_ip}: {ports}")
    else:
         log.debug(f"Regex did not find a 'Ports:' line with open ports for host {target_ip} in the provided gnmap content.")

    # Return sorted list of integers
    return sorted([int(p) for p in ports])


# --- NEW Function for Phase 1 Filtering ---
def parse_gnmap_filter_no_open(gnmap_content, ignore_port=None):
    """
    Parses Phase 1 GNMAP content. Returns a set of IPs that had at least
    one 'open' or 'open|filtered' port, AND filters out hosts where the
    *only* open port is the `ignore_port`.
    """
    potentially_live_hosts = set()
    # Pattern to find hosts marked as Up
    up_host_pattern = re.compile(r"^Host:\s+([\d.:a-fA-F]+)\s+(?:\(.*\)\s+)?Status:\s+Up", re.MULTILINE)

    log.debug(f"Starting Phase 1 filter. Ignore Port: {ignore_port}")

    # Find all 'Up' hosts first
    all_up_hosts = set()
    for match in up_host_pattern.finditer(gnmap_content):
        all_up_hosts.add(match.group(1))

    log.debug(f"Found {len(all_up_hosts)} hosts marked 'Up' in Phase 1.")

    # Now check ports for each 'Up' host
    for ip in all_up_hosts:
        open_ports = parse_gnmap_ports_for_host(gnmap_content, ip)

        if not open_ports:
            # Host is Up, but no open ports found in the scan results (all closed/filtered)
            log.debug(f"Filtering host {ip}: No 'open' or 'open|filtered' ports found.")
            continue # Skip this host

        # Apply ignore_port logic
        if ignore_port is not None:
            ignore_port_int = int(ignore_port) # Ensure it's int for comparison
            if len(open_ports) == 1 and open_ports[0] == ignore_port_int:
                log.debug(f"Filtering host {ip}: Only ignored port {ignore_port} was open.")
                continue # Skip this host if only the ignored port is open

        # If we reach here, the host has open ports and is not filtered by ignore_port
        potentially_live_hosts.add(ip)
        log.debug(f"Keeping host {ip} for Phase 3 (Ports: {open_ports}).")

    log.info(f"Phase 1 filter complete. Kept {len(potentially_live_hosts)} hosts with relevant open ports.")
    return potentially_live_hosts


def parse_gnmap_all_open_ports(gnmap_content):
    """Parses .gnmap to find all unique open or open|filtered ports across all hosts."""
    port_pattern = re.compile(r"(\d+)/(?:open|open\|filtered)")
    ports = set(port_pattern.findall(gnmap_content))
    # Return sorted list of integers
    return sorted([int(p) for p in ports])


def run_deep_scan(ip, scan_title_dir,  scan_title, gnmap_content_for_ports):
    """Task for running the Phase 4 deep scan on a single IP."""
    output_prefix = scan_title_dir / f"{scan_title}_phase4_DeepScan_HOST_{ip.replace(':', '_')}" # IPv6 safe filename
    xml_file = output_prefix.with_suffix(".xml")

    # Check if already scanned (using .xml as the primary indicator)
    if xml_file.exists():
        # Return a specific status for skipped-existing
        return ip, "skipped_exists", f"Skipped {ip}: Output exists ({xml_file.name})"

    # Get ports for this specific host from the relevant pre-loaded gnmap content
    ports_to_scan = parse_gnmap_ports_for_host(gnmap_content_for_ports, ip)

    if not ports_to_scan:
        # This should theoretically not happen if hosts_for_deep_scan is generated correctly,
        # but serves as a safeguard.
        log.warning(f"Deep scan called for {ip} but no open ports found in provided content. Skipping.")
        return ip, "skipped_no_ports", f"Skipped {ip}: No open ports found in provided source"

    port_str = ",".join(map(str, ports_to_scan))
    # Status message for starting scan
    start_msg = f"Starting deep scan on {ip} (Ports: {port_str})"
    log.info(start_msg) # Log start

    nmap_cmd_base = [
        "nmap", "-A", "-T4",
        "--max-retries", "3",
        "--max-rtt-timeout", "300ms",
        "--host-timeout", "8m",
        "-Pn",
        "-p", port_str,
        ip,
        "-oA", str(output_prefix) # Nmap needs string path
    ]
    # Add -6 for IPv6 if needed
    nmap_cmd = ["nmap", "-6"] + nmap_cmd_base[1:] if ':' in ip else nmap_cmd_base

    try:
        # Run command without capturing/checking return code here, will rely on logs/output parsing if needed
        # Let run_command handle logging and exception raising
        stdout, stderr = run_command(nmap_cmd, cwd=scan_title_dir, check=True, description=f"Deep Scan {ip}")

        # Basic check in stdout/stderr for common issues even if return code is 0
        if "Note: Host seems down" in stdout or "Failed to resolve" in stdout:
             log.warning(f"Deep scan for {ip} completed but Nmap noted host seemed down/unresolved.")
             return ip, "warning_down", f"Completed {ip} with warning (host down?)"
        else:
            return ip, "success", f"Completed {ip}"

    except FileNotFoundError:
         # Error already logged by run_command
         return ip, "failed", f"Failed {ip}: Nmap not found"
    except subprocess.CalledProcessError as e:
        # Error already logged by run_command
        return ip, "failed", f"Failed {ip} (Code: {e.returncode})"
    except Exception as e:
        log.exception(f"Unexpected error during deep scan for {ip}")
        return ip, "failed", f"Failed {ip} (Error: {type(e).__name__})"

# --- Main Execution ---
def main():
    # --- Argument Parser ---
    parser = argparse.ArgumentParser(
        description="Perform a multi-phase network scan using nmap, applying filters and showing progress.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # Changed required positional args to optional flags
    parser.add_argument("-s", "--scan-title", help="A unique name for this scan (used for directory).")
    parser.add_argument("-L", "--host-list", help="Path to the file containing target IPs.")

    # Optional args with defaults
    parser.add_argument("-t", "--top-ports", type=int, default=1000, help="Number of top ports for Phase 1.")
    parser.add_argument("-i", "--ignore-port", type=int, default=None, metavar='PORT', help="Exclude hosts from Phase 3/4 if only this port is open in Phase 1.")
    parser.add_argument("--skip-ping-sweep", action="store_true", help="Skip the Phase 2 ping sweep.")
    parser.add_argument("--phase3", default="-p-",
                        help="Phase 3 port spec ('-p-', '--top-ports X', 'skip', etc.). Use 'skip' to rely only on Phase 1 ports.")
    parser.add_argument("-j", "--parallel-scans", type=int, default=35, help="Number of parallel deep scans (Phase 4).") # Reduced default
    parser.add_argument("-o", "--output-dir", default=".", help="Parent directory for scan results.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")
    parser.add_argument("-f", "--force-overwrite", action="store_true", help="Force re-running scans even if output files exist.")

    args = parser.parse_args()

    # --- Root Check ---
    try:
        if os.name == 'posix' and os.geteuid() != 0:
            print_red("Error: This script requires root privileges (or sudo) for SYN scans (-sS).")
            sys.exit(1)
    except AttributeError: # Handle non-POSIX systems where geteuid doesn't exist
         print_yellow("Warning: Could not check for root privileges on this OS. SYN scans might fail if not run as administrator/root.")


    # --- Interactive Prompts (if args missing) ---
    print_blue("--- Scan Configuration ---")

    # Scan Title (Required)
    if args.scan_title is None:
        args.scan_title = prompt_user(
            "Enter a unique scan title (e.g., ProjectX_Q1_Scan). This should be an existing directory containing the target list: ",
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
    print_yellow("Note: Phase 3 will only target hosts that had open ports discovered in Phase 1/2.")
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

    # Output Directory
    print(f"Output directory base: {args.output_dir}")

    # --- Setup Output Directory ---
    base_output_dir = Path(args.output_dir)
    scan_title_dir = base_output_dir / args.scan_title
    try:
        scan_title_dir.mkdir(parents=True, exist_ok=True)
        # Use print here, before logging is configured
        print(f"{Fore.BLUE}Output directory: {scan_title_dir.resolve()}{Style.RESET_ALL}")
    except OSError as e:
        print_red(f"Error creating output directory {scan_title_dir}: {e}")
        sys.exit(1)

    # --- <<< CONFIGURE LOGGING >>> ---
    log_file = scan_title_dir / f"{args.scan_title}_scan.log"
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_format = '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s' # Format for the file

    logging.basicConfig(
        level=log_level,        # Set level (DEBUG or INFO)
        format=log_format,      # Use defined format
        filename=log_file,      # <<< Log to this file >>>
        filemode='a',           # Append ('w' would overwrite)
        force=True              # <<< Important: Ensures this config applies even if logging was used before
    )

    global log
    log = logging.getLogger("bulkScan")

    # You can now use log.info(), log.debug() etc. They will write to the file.
    log.info(f"--- Logging started. Level: {logging.getLevelName(log_level)}. Output File: {log_file} ---")

    # --- Change Directory and Start Scan ---
    original_cwd = Path.cwd()
    try:
        os.chdir(scan_title_dir)
        current_scan_dir = Path(".") # Use relative path now
        log.info(f"Changed working directory to: {current_scan_dir.resolve()}")

        print_yellow(f"\n--- Starting Scan: {args.scan_title} ---")
        print_yellow(f"--- Target List: {host_file.resolve()} ---")
        print_yellow(f"--- Output Dir: {current_scan_dir.resolve()} ---")
        print_yellow(f"--- Phase 1 Ports: {args.top_ports} ---")
        print_yellow(f"--- Ignore Port Filter: {args.ignore_port if args.ignore_port is not None else 'None'} ---")
        print_yellow(f"--- Skip Ping Sweep: {'Yes' if args.skip_ping_sweep else 'No'} ---")
        print_yellow(f"--- Phase 3 Spec: {args.phase3} ---")
        print_yellow(f"--- Phase 4 Parallelism: {args.parallel_scans} ---")
        print_yellow(f"--- Force Overwrite: {'Yes' if args.force_overwrite else 'No'} ---")
        time.sleep(1) 

        # Define file paths relative to current_scan_dir
        phase1_output_prefix = f"{args.scan_title}_phase1_Top{args.top_ports}Ports"
        phase1_gnmap_path = current_scan_dir / f"{phase1_output_prefix}.gnmap"
        phase1_xml_path = current_scan_dir / f"{phase1_output_prefix}.xml" # Check XML for completion too

        phase2_output_prefix = f"{args.scan_title}_phase2_PingSweep"
        phase2_gnmap_path = current_scan_dir / f"{phase2_output_prefix}.gnmap"

        phase3_output_prefix = f"{args.scan_title}_phase3_Port_Disco"
        phase3_gnmap_path = current_scan_dir / f"{phase3_output_prefix}.gnmap"
        phase3_xml_path = current_scan_dir / f"{phase3_output_prefix}.xml"

        live_hosts_file = current_scan_dir / f"{args.scan_title}_phase3_target_hosts.txt" # Renamed for clarity
        open_ports_file = current_scan_dir / f"{args.scan_title}_all_open_ports.txt"
        hosts_for_deep_scan_file = current_scan_dir / f"{args.scan_title}_phase4_target_hosts.txt" # Hosts actually getting deep scan

        # --- Phase 1: Discovery ---
        phase1_content = None
        if not args.force_overwrite and phase1_xml_path.exists(): # Check XML as indicator of completion
            print_purple(f"[*] Skipping Phase 1: Output file {phase1_xml_path.name} already exists.")
            try:
                 phase1_content = phase1_gnmap_path.read_text() # Still need content if exists
                 log.info(f"Read existing Phase 1 GNMAP content from {phase1_gnmap_path.name}")
            except Exception as e:
                 print_red(f"[!] Error reading existing Phase 1 gnmap file: {e}. Cannot apply filters.")
                 # Decide if this is fatal, maybe exit?
                 sys.exit(1)
        else:
            phase1_cmd = [
                "nmap", "-sS", "-T4",
                "--max-retries", "1", "--max-rtt-timeout", "300ms", "--host-timeout", "3m",
                "--max-scan-delay", "5ms", "--min-rate", "800", # Adjusted delay
                "-Pn", "-n",
                "-iL", str(host_file.resolve()),
                "--top-ports", str(args.top_ports),
                "-oA", phase1_output_prefix
            ]
            try:
                # Let run_command handle printing status
                run_command(phase1_cmd, description=f"Phase 1: Discovery Scan (Top {args.top_ports} Ports, No Ping)")
                # Read content after successful run
                if phase1_gnmap_path.exists():
                     phase1_content = phase1_gnmap_path.read_text()
                else:
                     print_red("[!] Phase 1 completed but GNMAP output not found!")
                     sys.exit(1)
            except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
                print_red(f"[!] Phase 1 failed: {e}")
                sys.exit(1)

        if phase1_content is None:
            print_red("[!] Critical: Could not obtain Phase 1 GNMAP content. Exiting.")
            sys.exit(1)

        # --- Apply Phase 1 Filtering ---
        print_blue("[+] Applying Phase 1 Filter (Keep hosts with open ports, excluding ignore-port-only)")
        phase1_hosts_passed_filter = parse_gnmap_filter_no_open(phase1_content, args.ignore_port)
        print_green(f"    {len(phase1_hosts_passed_filter)} hosts passed Phase 1 filtering.")


        # --- Phase 2: Ping Sweep ---
        phase2_hosts = set()
        if not args.skip_ping_sweep:
            phase2_gnmap_content = None
            if not args.force_overwrite and phase2_gnmap_path.exists():
                print_purple(f"[*] Skipping Phase 2 Scan: Output file {phase2_gnmap_path.name} already exists.")
                try:
                    phase2_gnmap_content = phase2_gnmap_path.read_text()
                except Exception as e:
                     print_red(f"[!] Error reading existing Phase 2 gnmap file: {e}")
            else:
                phase2_cmd = [
                    "nmap", "-sn", "-T4",
                    "--max-retries", "1", "--max-rtt-timeout", "300ms", "--host-timeout", "5m",
                    "-n",
                    "-iL", str(host_file.resolve()),
                    "-oA", phase2_output_prefix
                ]
                try:
                    run_command(phase2_cmd, description="Phase 2: Ping Sweep")
                    if phase2_gnmap_path.exists():
                         phase2_gnmap_content = phase2_gnmap_path.read_text()
                    else:
                         print_yellow("[!] Phase 2 ran but output GNMAP not found.")
                except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
                    print_red(f"[!] Phase 2 failed: {e}") # Non-fatal

            # Parse content if available
            if phase2_gnmap_content:
                 try:
                     phase2_hosts = parse_gnmap_live_hosts(phase2_gnmap_content)
                     print_green(f"    Extracted {len(phase2_hosts)} hosts marked 'Up' from Phase 2 results.")
                 except Exception as e:
                     print_red(f"[!] Error parsing Phase 2 gnmap content: {e}")
            else:
                log.info("No Phase 2 gnmap content to parse.")

        else:
            print_yellow("[+] Skipping Phase 2 Ping Sweep.")


        # --- Determine Final Host List for Phase 3 ---
        print_blue("[+] Combining Filtered Phase 1 and Phase 2 Hosts for Phase 3 Targeting")
        # Combine hosts that passed the P1 filter with any hosts found live in P2
        final_hosts_for_phase3 = sorted(list(phase1_hosts_passed_filter.union(phase2_hosts)))

        if final_hosts_for_phase3:
            try:
                with open(live_hosts_file, "w") as f:
                    for host in final_hosts_for_phase3:
                        f.write(host + "\n")
                print_green(f"[+] {len(final_hosts_for_phase3)} hosts targeted for Phase 3 saved to {live_hosts_file.name}")
            except IOError as e:
                print_red(f"Error writing Phase 3 target hosts file {live_hosts_file.name}: {e}")
                sys.exit(1)
        else:
            print_red("[!] Warning: No hosts remaining after filtering and ping sweep. Skipping Phase 3 & 4.")
            # No need to exit here, subsequent phases will check list length


        # --- Phase 3: Port Discovery ---
        phase3_completed = False
        phase3_content = None # To store content if scan runs or exists
        if not final_hosts_for_phase3:
            print_red("[!] Skipping Phase 3: No target hosts.")
        elif args.phase3.lower() == 'skip':
            print_blue("[+] Phase 3: Skipped by user request.")
            print_yellow("    Phase 4 will rely on Phase 1 results for port lists.")
            # No file copy needed, logic below handles fallback
            phase3_completed = False # Explicitly false if skipped
        else:
            if not args.force_overwrite and phase3_xml_path.exists():
                 print_purple(f"[*] Skipping Phase 3 Scan: Output file {phase3_xml_path.name} already exists.")
                 phase3_completed = True
                 try:
                      phase3_content = phase3_gnmap_path.read_text()
                 except Exception as e:
                      print_red(f"[!] Error reading existing Phase 3 gnmap file: {e}")
                      phase3_completed = False # Cannot use if unreadable
            else:
                try:
                     phase3_nmap_opts = shlex.split(args.phase3)
                except ValueError as e:
                     print_red(f"Error parsing Phase 3 options '{args.phase3}': {e}. Defaulting to '-p-'.")
                     phase3_nmap_opts = ["-p-"]

                phase3_cmd_base = [
                    "nmap", "-sS", "-Pn", "-n", "-T4",
                    "--max-retries", "2", "--max-rtt-timeout", "500ms",
                    "--host-timeout", "15m",
                    "--max-scan-delay", "5ms", "--min-rate", "800",
                    "-iL", str(live_hosts_file.resolve()), # Use absolute path to be safe
                ]
                phase3_cmd_base.extend(phase3_nmap_opts)
                phase3_cmd_base.extend(["-oA", phase3_output_prefix])

                # Add -6 if needed
                phase3_cmd = ["nmap", "-6"] + phase3_cmd_base[1:] if any(':' in ip for ip in final_hosts_for_phase3) else phase3_cmd_base


                try:
                    # Pass description to run_command
                    run_command(phase3_cmd, description=f"Phase 3: Port Discovery Scan ({args.phase3}) on {len(final_hosts_for_phase3)} Hosts")
                    phase3_completed = True
                    # Read content after successful run
                    if phase3_gnmap_path.exists():
                         phase3_content = phase3_gnmap_path.read_text()
                    else:
                         print_red("[!] Phase 3 completed but GNMAP output not found!")
                         phase3_completed = False # Cannot use if missing
                except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
                    print_red(f"[!] Phase 3 failed: {e}")
                    phase3_completed = False

        # --- Extract All Unique Open Ports (Overall Summary) ---
        # This is just for the summary file, not for targeting Phase 4
        open_ports_list = []
        gnmap_for_overall_ports_path = None
        source_desc = "None"

        if phase3_completed and phase3_content:
            gnmap_for_overall_ports_path = phase3_gnmap_path
            source_desc = "Phase 3"
        elif phase1_content: # Fallback to Phase 1 if Phase 3 skipped/failed
             gnmap_for_overall_ports_path = phase1_gnmap_path
             source_desc = "Phase 1"

        if gnmap_for_overall_ports_path:
            print_blue(f"[+] Extracting All Unique Open Ports found in {source_desc} results")
            try:
                # Read content again in case it was from an existing file
                content_to_parse = gnmap_for_overall_ports_path.read_text()
                open_ports_list = parse_gnmap_all_open_ports(content_to_parse)
            except Exception as e:
                print_red(f"[!] Error parsing {gnmap_for_overall_ports_path.name} for overall ports: {e}")

        if open_ports_list:
            try:
                port_str = ",".join(map(str, open_ports_list))
                open_ports_file.write_text(port_str + "\n")
                print_green(f"    All unique open ports ({len(open_ports_list)}) from {source_desc} saved to {open_ports_file.name}")
            except IOError as e:
                print_red(f"Error writing open ports file {open_ports_file.name}: {e}")
        else:
            print_yellow(f"[!] Warning: No overall open ports found in {source_desc} scan results.")


        # --- Determine Hosts and Content for Deep Scan (Phase 4) ---
        hosts_for_deep_scan = []
        gnmap_content_for_deep_scan_ports = None
        source_desc_p4 = "None"

        # Prioritize Phase 3 results if available and successful
        if phase3_completed and phase3_content:
             gnmap_content_for_deep_scan_ports = phase3_content
             source_desc_p4 = "Phase 3"
             print_blue("[+] Using Phase 3 results to determine ports for Deep Scan.")
        elif phase1_content: # Fallback to Phase 1 content
             gnmap_content_for_deep_scan_ports = phase1_content
             source_desc_p4 = "Phase 1"
             print_yellow("[!] Phase 3 skipped or failed. Using Phase 1 results to determine ports for Deep Scan.")
        else:
             print_red("[!] No usable .gnmap content found from Phase 1 or 3. Cannot determine ports for Deep Scan.")

        # Populate hosts_for_deep_scan list using the chosen content
        if gnmap_content_for_deep_scan_ports and final_hosts_for_phase3:
             print_blue(f"[+] Identifying hosts from Phase 3 target list ({len(final_hosts_for_phase3)}) with open ports in {source_desc_p4} results.")
             count_with_ports = 0
             for ip in final_hosts_for_phase3:
                  # Check if this host has open ports in the selected source content
                  # Note: ignore_port filter was already applied when creating phase1_hosts_passed_filter
                  ports = parse_gnmap_ports_for_host(gnmap_content_for_deep_scan_ports, ip)
                  if ports:
                       hosts_for_deep_scan.append(ip)
                       count_with_ports += 1
                       log.debug(f"Host {ip} has open ports in {source_desc_p4}, adding to Phase 4 list.")
                  else:
                       log.debug(f"Host {ip} (targeted for P3) has no open ports listed in {source_desc_p4}. Skipping Phase 4.")

             print_green(f"    Found {count_with_ports} hosts with open ports in {source_desc_p4} results for Phase 4.")

             if hosts_for_deep_scan:
                 try:
                     with open(hosts_for_deep_scan_file, "w") as f:
                         for host in hosts_for_deep_scan: # Already sorted from final_hosts_for_phase3
                             f.write(host + "\n")
                     print_green(f"    Phase 4 target list saved to {hosts_for_deep_scan_file.name}")
                 except IOError as e:
                     print_red(f"Error writing Phase 4 target hosts file {hosts_for_deep_scan_file.name}: {e}")
             else:
                 print_red("[!] No hosts found with open ports for the deep scan phase after checking relevant results.")


        # --- Phase 4: Deep Scan ---
        if not hosts_for_deep_scan:
            print_red("[!] Skipping Phase 4: No target hosts with open ports identified.")
        elif gnmap_content_for_deep_scan_ports is None:
             print_red("[!] Skipping Phase 4: Missing GNMAP content to determine ports.")
        else:
            print_blue(f"\n[+] Phase 4: Starting Deep Scan on {len(hosts_for_deep_scan)} Hosts (using {args.parallel_scans} parallel threads)")

            # Use partial to pass fixed arguments to the worker function
            scan_func = partial(run_deep_scan,
                                scan_title_dir=current_scan_dir,
                                scan_title=args.scan_title,
                                gnmap_content_for_ports=gnmap_content_for_deep_scan_ports)

            results_summary = {'success': 0, 'skipped_exists': 0, 'skipped_no_ports': 0, 'warning_down': 0, 'failed': 0}
            completed_count = 0
            total_tasks = len(hosts_for_deep_scan)

            # Add start time
            phase4_start_time = time.time()

            with ThreadPoolExecutor(max_workers=args.parallel_scans) as executor:
                futures = {executor.submit(scan_func, ip): ip for ip in hosts_for_deep_scan}

                # Progress bar setup
                progress_bar_length = 50
                sys.stdout.write(f"    Progress: [{ ' ' * progress_bar_length }] 0% (0/{total_tasks})")
                sys.stdout.flush()

                for future in as_completed(futures):
                    ip = futures[future]
                    completed_count += 1
                    percentage = (completed_count / total_tasks) * 100
                    filled_length = int(progress_bar_length * completed_count // total_tasks)
                    bar = '#' * filled_length + ' ' * (progress_bar_length - filled_length)

                    # Calculate elapsed time and ETA
                    elapsed_time = time.time() - phase4_start_time
                    est_total_time = (elapsed_time / completed_count) * total_tasks if completed_count > 0 else 0
                    eta = est_total_time - elapsed_time
                    eta_str = f" ETA: {int(eta // 60)}m{int(eta % 60)}s" if eta > 0 else ""


                    # Update progress bar
                    progress_string = f"Progress: [{bar}] {percentage:.1f}% ({completed_count}/{total_tasks}){eta_str}"
                    sys.stdout.write(f"\r    {progress_string} ") # Overwrite previous progress line
                    sys.stdout.flush()


                    try:
                        target_ip, status_code, message = future.result()

                        # Update summary based on status code
                        if status_code in results_summary:
                             results_summary[status_code] += 1
                        else:
                             log.warning(f"Unknown status code from deep scan worker: {status_code}")
                             results_summary['failed'] += 1 # Count unknowns as failed

                        # Print status messages for non-success cases immediately
                        if status_code == "skipped_exists":
                             # Use \r to potentially overwrite ETA part of progress line
                             sys.stdout.write(f"\r    {progress_string} - {Fore.MAGENTA}Skipped (Exists): {target_ip}{Style.RESET_ALL}\n")
                             # Reprint progress bar on next line to keep it visible
                             sys.stdout.write(f"    {progress_string} ")
                             sys.stdout.flush()
                        elif status_code == "skipped_no_ports":
                             sys.stdout.write(f"\r    {progress_string} - {Fore.YELLOW}Skipped (No Ports): {target_ip}{Style.RESET_ALL}\n")
                             sys.stdout.write(f"    {progress_string} ")
                             sys.stdout.flush()
                        elif status_code == "warning_down":
                             sys.stdout.write(f"\r    {progress_string} - {Fore.YELLOW}Warning (Down?): {target_ip}{Style.RESET_ALL}\n")
                             sys.stdout.write(f"    {progress_string} ")
                             sys.stdout.flush()
                        elif status_code == "failed":
                             sys.stdout.write(f"\r    {progress_string} - {Fore.RED}FAILED: {message}{Style.RESET_ALL}\n")
                             sys.stdout.write(f"    {progress_string} ")
                             sys.stdout.flush()
                        # For 'success', just update the progress bar/ETA

                    except Exception as exc:
                        print_red(f'\n[!] Host {ip} generated an exception during Phase 4 future processing: {exc}')
                        log.exception(f"Phase 4 future exception for {ip}")
                        results_summary['failed'] += 1
                        # Reprint progress after error
                        sys.stdout.write(f"\r    {progress_string} ")
                        sys.stdout.flush()

            # Final newline after loop finishes
            print()
            print_green(f"[+] Phase 4 processing complete.")
            print_blue("    Summary:")
            print_green(f"      Successful Scans: {results_summary['success']}")
            print_purple(f"      Skipped (Already Existed): {results_summary['skipped_exists']}")
            print_yellow(f"      Skipped (No Ports Found): {results_summary['skipped_no_ports']}") # Should be 0 ideally
            print_yellow(f"      Warnings (Host Seemed Down): {results_summary['warning_down']}")
            print_red(f"      Failed Scans: {results_summary['failed']}")


        # --- Final Output ---
        print_blue(f"\n--- Scan {args.scan_title} Complete ---")
        print_blue(f"--- Results are in: {current_scan_dir.resolve()} ---")
        log.info(f"--- Scan {args.scan_title} Complete ---") 

    finally:
        # Ensure we change back to the original directory
        os.chdir(original_cwd)
        log.info(f"Changed back to original directory: {original_cwd}")
        os.chdir(original_cwd)
        logging.shutdown()

if __name__ == "__main__":
    main()
