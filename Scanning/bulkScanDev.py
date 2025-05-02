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

# --- Logging Setup ---
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
log = logging.getLogger("NetScanScript")

# --- Color Print Functions ---
def print_color(color, text):
    print(f"{color}{text}{Style.RESET_ALL}", flush=True)

def print_green(text): print_color(Fore.GREEN, text)
def print_yellow(text): print_color(Fore.YELLOW, text)
def print_red(text): print_color(Fore.RED, text)
def print_blue(text): print_color(Fore.BLUE, text)
def print_purple(text): print_color(Fore.MAGENTA, text)

# --- Helper Function for Prompts ---
def prompt_user(prompt_text, default=None, validation_func=None, error_msg="Invalid input."):
    prompt_suffix = f" [{default}]" if default is not None else ""
    while True:
        user_input = input(f"{Style.BRIGHT}{prompt_text}{Style.RESET_ALL}{prompt_suffix}: ").strip()
        if not user_input and default is not None:
            value = default
            print(f"Using default: {value}")
            break
        elif user_input:
            value = user_input
            if validation_func:
                if validation_func(value):
                    break
                else:
                    print_red(error_msg)
            else:
                break
        elif default is None:
             print_red("This field cannot be empty.")
    if isinstance(default, int):
        try: return int(value)
        except ValueError: return default
    elif isinstance(default, str) and default.isdigit():
        try: return int(value)
        except ValueError: return value
    return value

# --- Validation Functions ---
def is_valid_path(path_str):
    p = Path(path_str)
    return p.is_file() and os.access(p, os.R_OK)

def is_not_empty(value): return bool(value)
def is_positive_int(value):
    try: return int(value) > 0
    except ValueError: return False
def is_valid_phase3(value): return bool(value)
def is_yes_no(value): return value.lower() in ['y', 'n', 'yes', 'no']

# --- Nmap and Parsing Functions ---

def start_nmap_process(cmd_list, cwd=None, description="Starting Nmap Process"):
    """Starts an Nmap process using subprocess.Popen and returns the process object."""
    cmd_str = shlex.join(cmd_list)
    print_blue(f"[+] {description}")
    print_yellow(f"    Command: {cmd_str}")
    log.info(f"Starting command: {cmd_str} in {cwd or Path.cwd()}")
    try:
        process = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd)
        return process
    except FileNotFoundError:
        log.error(f"Error: Command not found: {cmd_list[0]}")
        print_red(f"    Error: Command not found: {cmd_list[0]}. Is nmap installed and in PATH?")
        raise
    except Exception as e:
        log.exception(f"An unexpected error occurred while starting command '{cmd_str}'")
        print_red(f"    An unexpected error occurred starting Nmap: {e}")
        raise

def count_unique_hosts_from_gnmap(gnmap_file_path):
    """Parses a growing .gnmap file and returns the count of unique host IPs found."""
    hosts = set()
    try:
        with open(gnmap_file_path, 'r') as f:
            for line in f:
                if line.startswith("Host: "):
                    parts = line.split()
                    if len(parts) > 1:
                        ip_address = parts[1]
                        if re.match(r"^[\d.:a-fA-F]+$", ip_address): # Basic IP format check
                             hosts.add(ip_address)
    except FileNotFoundError:
        return 0
    except Exception as e:
        log.warning(f"Error reading/parsing gnmap file '{gnmap_file_path}' during progress update: {e}")
        return 0
    return len(hosts)

def monitor_nmap_progress(process: subprocess.Popen, gnmap_path: Path, description: str, poll_interval: int = 3): # Reduced poll interval
    """Monitors a running Nmap Popen process, showing progress based on gnmap file."""
    start_time = time.time()
    last_host_count = 0
    last_status_len = 0 # Keep track of the last status line length

    print_blue(f"    Monitoring {description} progress (checking {gnmap_path.name} every {poll_interval}s)...")

    try:
        while process.poll() is None:
            time.sleep(poll_interval)
            elapsed_time = time.time() - start_time
            elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))

            host_count = count_unique_hosts_from_gnmap(gnmap_path)
            if host_count > last_host_count:
                 log.info(f"Progress {description}: Found {host_count} hosts after {elapsed_str}")
                 last_host_count = host_count

            # Status line update
            status_line = f"    {description} running for {elapsed_str}... Found {host_count} hosts."
            # Use \r and pad with spaces to clear the previous line completely
            clear_line = " " * last_status_len
            sys.stdout.write(f"\r{clear_line}\r{Style.DIM}{status_line}{Style.RESET_ALL}")
            sys.stdout.flush()
            last_status_len = len(status_line) # Store current length

    except KeyboardInterrupt:
        print_red("\n[!] Scan interrupted by user during monitoring!")
        process.terminate()
        time.sleep(0.5); process.kill() # Try to ensure it stops
        print_red("    Nmap process terminated.")
        return False
    except Exception as e:
        print_red(f"\n[!] An error occurred during progress monitoring: {e}")
        log.exception("Error during progress monitoring loop")

    finally:
        # Ensure the final status line is cleared
        sys.stdout.write("\r" + " " * last_status_len + "\r")
        sys.stdout.flush()

    # --- Process finished, check final result ---
    stdout, stderr = process.communicate()
    if stdout: log.debug(f"Final stdout ({description}):\n{stdout.strip()}")
    if stderr:
        if process.returncode != 0: log.error(f"Final stderr ({description}):\n{stderr.strip()}")
        else: log.warning(f"Final stderr (RC=0) ({description}):\n{stderr.strip()}")

    if process.returncode == 0:
        final_host_count = count_unique_hosts_from_gnmap(gnmap_path) # Get final count
        elapsed_time = time.time() - start_time
        elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
        print_green(f"    {description} completed successfully in {elapsed_str}. Found {final_host_count} hosts.")
        return True
    else:
        print_red(f"    {description} failed (Code: {process.returncode}). Check logs.")
        return False


# ADDED quiet parameter
def run_command(cmd_list, cwd=None, check=True, description="Running command", quiet=False):
    """Runs a command using subprocess, logs output, uses color, optionally quiet."""
    cmd_str = shlex.join(cmd_list) # For logging/display
    # Only print description and command if not quiet
    if not quiet:
        print_blue(f"[+] {description}")
        print_yellow(f"    Command: {cmd_str}")
    log.info(f"Running command: {cmd_str} in {cwd or Path.cwd()}")
    try:
        process = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd)
        stdout, stderr = process.communicate()

        if stdout: log.debug(f"Command stdout:\n{stdout.strip()}")
        if stderr:
            if process.returncode != 0: log.error(f"Command stderr:\n{stderr.strip()}")
            else: log.warning(f"Command stderr (RC=0):\n{stderr.strip()}")

        if check and process.returncode != 0:
            log.error(f"Command failed with exit code {process.returncode}: {cmd_str}")
            error_details = f"Stderr:\n{stderr.strip()}" if stderr.strip() else "No stderr."
            # Only print failure message if not quiet
            if not quiet:
                print_red(f"    Command failed (Code: {process.returncode}). Check logs.")
            raise subprocess.CalledProcessError(process.returncode, cmd_list, output=stdout, stderr=error_details)

        # Only print success message if not quiet
        if not quiet:
            print_green(f"    Command completed successfully.")
        log.info(f"Command finished successfully: {cmd_str}")
        return stdout, stderr

    except FileNotFoundError:
        log.error(f"Error: Command not found: {cmd_list[0]}")
        # Only print error message if not quiet
        if not quiet:
            print_red(f"    Error: Command not found: {cmd_list[0]}. Is nmap installed and in PATH?")
        raise
    except Exception as e:
        log.exception(f"An unexpected error occurred while running command '{cmd_str}'")
         # Only print error message if not quiet
        if not quiet:
            print_red(f"    An unexpected error occurred: {e}")
        raise

# --- Other Parsing Functions (Unchanged) ---
def parse_gnmap_live_hosts(gnmap_content):
    live_hosts = set()
    up_host_pattern = re.compile(r"^Host:\s+([\d.:a-fA-F]+)\s+(?:\(.*\)\s+)?Status:\s+Up", re.MULTILINE)
    for match in up_host_pattern.finditer(gnmap_content):
         ip = match.group(1); live_hosts.add(ip); log.debug(f"Found Up host: {ip}")
    log.info(f"Parsed gnmap content. Found {len(live_hosts)} hosts marked 'Up'.")
    return live_hosts

def parse_gnmap_ports_for_host(gnmap_content, target_ip):
    ports = set()
    host_line_pattern = re.compile(r"^Host:\s+" + re.escape(target_ip) + r"\s*(?:\(.*\)\s*)?.*?\sPorts:\s+(.*)", re.MULTILINE)
    port_pattern = re.compile(r"(\d+)/(?:open|open\|filtered)")
    match = host_line_pattern.search(gnmap_content)
    if match:
        ports_str = match.group(1); log.debug(f"Ports string for {target_ip}: {ports_str[:100]}...")
        found_ports = port_pattern.findall(ports_str); ports.update(found_ports)
        log.debug(f"Extracted ports for {target_ip}: {ports}")
    else: log.debug(f"No 'Ports:' line found for {target_ip}.")
    return sorted([int(p) for p in ports])

def parse_gnmap_filter_no_open(gnmap_content, ignore_port=None):
    potentially_live_hosts = set()
    up_host_pattern = re.compile(r"^Host:\s+([\d.:a-fA-F]+)\s+(?:\(.*\)\s+)?Status:\s+Up", re.MULTILINE)
    log.debug(f"Phase 1 filter. Ignore Port: {ignore_port}")
    all_up_hosts = set(); [all_up_hosts.add(match.group(1)) for match in up_host_pattern.finditer(gnmap_content)]
    log.debug(f"Found {len(all_up_hosts)} hosts 'Up' in Phase 1.")
    for ip in all_up_hosts:
        open_ports = parse_gnmap_ports_for_host(gnmap_content, ip)
        if not open_ports: log.debug(f"Filtering {ip}: No open ports."); continue
        if ignore_port is not None:
            ignore_port_int = int(ignore_port)
            if len(open_ports) == 1 and open_ports[0] == ignore_port_int:
                log.debug(f"Filtering {ip}: Only ignored port {ignore_port} open."); continue
        potentially_live_hosts.add(ip); log.debug(f"Keeping {ip} (Ports: {open_ports}).")
    log.info(f"Phase 1 filter kept {len(potentially_live_hosts)} hosts.")
    return potentially_live_hosts

def parse_gnmap_all_open_ports(gnmap_content):
    port_pattern = re.compile(r"(\d+)/(?:open|open\|filtered)")
    ports = set(port_pattern.findall(gnmap_content))
    return sorted([int(p) for p in ports])

# MODIFIED run_deep_scan to call run_command quietly
def run_deep_scan(ip, scan_title_dir, gnmap_content_for_ports):
    output_prefix = scan_title_dir / f"phase4_DeepScan_HOST_{ip.replace(':', '_')}"
    xml_file = output_prefix.with_suffix(".xml")
    if xml_file.exists():
        log.info(f"Skipping deep scan for {ip}: Output exists ({xml_file.name})")
        return ip, "skipped_exists"
    ports_to_scan = parse_gnmap_ports_for_host(gnmap_content_for_ports, ip)
    if not ports_to_scan:
        log.warning(f"Deep scan called for {ip} but no open ports found. Skipping.")
        return ip, "skipped_no_ports"
    port_str = ",".join(map(str, ports_to_scan))
    log.info(f"Starting deep scan on {ip} (Ports: {port_str})") # Log start
    nmap_cmd_base = ["nmap", "-A", "-T4", "--max-retries", "3", "--max-rtt-timeout", "300ms", "--host-timeout", "8m", "-Pn", "-p", port_str, ip, "-oA", str(output_prefix)]
    nmap_cmd = ["nmap", "-6"] + nmap_cmd_base[1:] if ':' in ip else nmap_cmd_base
    try:
        # Call run_command quietly, only log details, don't print command info to console
        stdout, stderr = run_command(nmap_cmd, cwd=scan_title_dir, check=True, quiet=True) # ADDED quiet=True

        if "Note: Host seems down" in stdout or "Failed to resolve" in stdout:
             log.warning(f"Deep scan for {ip} completed with host down/unresolved warning.")
             return ip, "warning_down"
        else:
            log.info(f"Deep scan completed successfully for {ip}") # Log success
            return ip, "success"
    except FileNotFoundError: return ip, "failed" # Error logged/printed by run_command
    except subprocess.CalledProcessError as e:
        log.error(f"Deep scan failed for {ip} (Code: {e.returncode})") # Error logged/printed by run_command
        return ip, "failed"
    except Exception as e:
        log.exception(f"Unexpected error during deep scan for {ip}")
        return ip, "failed"


# --- Main Execution ---
def main():
    # --- Argument Parser ---
    # (Same as before)
    parser = argparse.ArgumentParser(description="Perform a multi-phase network scan using nmap.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-s", "--scan-title", help="A unique name for this scan.")
    parser.add_argument("-L", "--host-list", help="Path to the file containing target IPs.")
    parser.add_argument("-t", "--top-ports", type=int, default=1000, help="Number of top ports for Phase 1.")
    parser.add_argument("-i", "--ignore-port", type=int, default=None, metavar='PORT', help="Exclude hosts if only this port is open in Phase 1.")
    parser.add_argument("--skip-ping-sweep", action="store_true", help="Skip the Phase 2 ping sweep.")
    parser.add_argument("--phase3", default="-p-", help="Phase 3 port spec ('-p-', '--top-ports X', 'skip', etc.).")
    parser.add_argument("-j", "--parallel-scans", type=int, default=35, help="Number of parallel deep scans (Phase 4).")
    parser.add_argument("-o", "--output-dir", default=".", help="Parent directory for scan results.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")
    parser.add_argument("-f", "--force-overwrite", action="store_true", help="Force re-running scans even if output files exist.")
    args = parser.parse_args()

    # --- Configure Logging Level ---
    # (Same as before)
    if args.verbose: log.setLevel(logging.DEBUG)
    else: log.setLevel(logging.INFO)

    # --- Root Check ---
    # (Same as before)
    try:
        if os.name == 'posix' and os.geteuid() != 0: print_red("Error: Requires root privileges."); sys.exit(1)
    except AttributeError: print_yellow("Warning: Could not check root privileges.")

    # --- Interactive Prompts ---
    # (Same as before, simplified for brevity)
    print_blue("--- Scan Configuration ---")
    if args.scan_title is None: args.scan_title = prompt_user("Scan title", validation_func=is_not_empty)
    else: print(f"Scan Title: {args.scan_title}")
    if args.host_list is None: args.host_list = prompt_user("Host list file path", validation_func=is_valid_path)
    else:
        if not is_valid_path(args.host_list): print_red(f"Host list invalid: {args.host_list}"); sys.exit(1)
        print(f"Host List: {args.host_list}")
    host_file = Path(args.host_list)
    args.top_ports = prompt_user(f"Top ports (Phase 1)", default=args.top_ports, validation_func=is_positive_int)
    ignore_port_input = input(f"Ignore port (if only) [{args.ignore_port or 'None'}]: ").strip()
    if ignore_port_input:
        try: port_val = int(ignore_port_input); args.ignore_port = port_val if 1 <= port_val <= 65535 else None
        except ValueError: args.ignore_port = None
    if args.ignore_port is None and ignore_port_input: print_red("Invalid port. Ignoring exclusion.")
    log.info(f"Ignore Port: {args.ignore_port}")
    skip_ping_input = prompt_user("Skip Ping Sweep (Y/n)", default='N' if not args.skip_ping_sweep else 'Y', validation_func=is_yes_no)
    args.skip_ping_sweep = skip_ping_input.lower().startswith('y')
    args.phase3 = prompt_user(f"Phase 3 spec ('skip', '-p-', etc.)", default=args.phase3, validation_func=is_valid_phase3)
    args.parallel_scans = prompt_user(f"Parallel scans (Phase 4)", default=args.parallel_scans, validation_func=is_positive_int)
    print(f"Output directory base: {args.output_dir}")

    # --- Setup Output Directory ---
    # (Same as before)
    base_output_dir = Path(args.output_dir); scan_title_dir = base_output_dir / args.scan_title
    try: scan_title_dir.mkdir(parents=True, exist_ok=True); log.info(f"Output dir: {scan_title_dir.resolve()}")
    except OSError as e: print_red(f"Error creating output dir {scan_title_dir}: {e}"); sys.exit(1)

    # --- Change Directory and Start Scan ---
    original_cwd = Path.cwd()
    try:
        os.chdir(scan_title_dir)
        current_scan_dir = Path(".")

        # Print summary - same as before
        print_yellow(f"\n--- Starting Scan: {args.scan_title} ---")
        print_yellow(f"--- Target List: {host_file.resolve()} ---")
        print_yellow(f"--- Output Dir: {current_scan_dir.resolve()} ---")
        # ... (print other settings) ...
        time.sleep(1)

        # Define file paths - same as before
        phase1_output_prefix = f"{args.scan_title}_phase1_Top{args.top_ports}Ports"
        phase1_gnmap_path = current_scan_dir / f"{phase1_output_prefix}.gnmap"
        phase1_xml_path = current_scan_dir / f"{phase1_output_prefix}.xml"
        phase2_output_prefix = f"{args.scan_title}_phase2_PingSweep"
        phase2_gnmap_path = current_scan_dir / f"{phase2_output_prefix}.gnmap"
        phase3_output_prefix = f"{args.scan_title}_phase3_Port_Disco"
        phase3_gnmap_path = current_scan_dir / f"{phase3_output_prefix}.gnmap"
        phase3_xml_path = current_scan_dir / f"{phase3_output_prefix}.xml"
        live_hosts_file = current_scan_dir / f"{args.scan_title}_phase3_target_hosts.txt"
        open_ports_file = current_scan_dir / f"{args.scan_title}_all_open_ports.txt"
        hosts_for_deep_scan_file = current_scan_dir / f"{args.scan_title}_phase4_target_hosts.txt"


        # --- Phase 1: Discovery ---
        phase1_content = None
        phase1_success = False
        if not args.force_overwrite and phase1_xml_path.exists():
            print_purple(f"[*] Phase 1: Output file {phase1_xml_path.name} already exists.")
            try:
                 phase1_content = phase1_gnmap_path.read_text()
                 log.info(f"Read existing Phase 1 GNMAP: {phase1_gnmap_path.name}")
                 print_green(f"    Using existing Phase 1 results.")
                 phase1_success = True
            except Exception as e: print_red(f"[!] Error reading existing Phase 1 file: {e}"); sys.exit(1)
        else:
            phase1_cmd = ["nmap", "-sS", "-T4", "--max-retries", "1", "--max-rtt-timeout", "300ms", "--host-timeout", "3m", "--max-scan-delay", "5ms", "--min-rate", "800", "-Pn", "-n", "-iL", str(host_file.resolve()), "--top-ports", str(args.top_ports), "-oA", phase1_output_prefix]
            try:
                nmap_process = start_nmap_process(phase1_cmd, description="Phase 1: Discovery Scan")
                phase1_success = monitor_nmap_progress(nmap_process, phase1_gnmap_path, "Phase 1") # Monitor runs here
                if phase1_success and phase1_gnmap_path.exists(): phase1_content = phase1_gnmap_path.read_text()
                elif phase1_success: print_red("[!] Phase 1 OK but GNMAP missing!"); phase1_success = False
            except (FileNotFoundError, Exception) as e: print_red(f"[!] Phase 1 failed start: {e}"); sys.exit(1)
        if not phase1_success: print_red("[!] Phase 1 failed. Exiting."); sys.exit(1)
        if phase1_content is None: print_red("[!] Phase 1 content missing. Exiting."); sys.exit(1)

        # --- Apply Phase 1 Filtering ---
        print_blue("[+] Applying Phase 1 Filter")
        phase1_hosts_passed_filter = parse_gnmap_filter_no_open(phase1_content, args.ignore_port)
        print_green(f"    {len(phase1_hosts_passed_filter)} hosts passed.")

        # --- Phase 2: Ping Sweep ---
        phase2_hosts = set()
        if not args.skip_ping_sweep:
            phase2_gnmap_content = None
            phase2_success = False
            if not args.force_overwrite and phase2_gnmap_path.exists():
                print_purple(f"[*] Phase 2: Output file {phase2_gnmap_path.name} exists.")
                try: phase2_gnmap_content = phase2_gnmap_path.read_text(); print_green(f"    Using existing Phase 2 results."); phase2_success = True
                except Exception as e: print_red(f"[!] Error reading existing Phase 2 file: {e}")
            else:
                phase2_cmd = ["nmap", "-sn", "-T4", "--max-retries", "1", "--max-rtt-timeout", "300ms", "--host-timeout", "5m", "-n", "-iL", str(host_file.resolve()), "-oA", phase2_output_prefix]
                try:
                    nmap_process = start_nmap_process(phase2_cmd, description="Phase 2: Ping Sweep")
                    phase2_success = monitor_nmap_progress(nmap_process, phase2_gnmap_path, "Phase 2") # Monitor runs here
                    if phase2_success and phase2_gnmap_path.exists(): phase2_gnmap_content = phase2_gnmap_path.read_text()
                    elif phase2_success: print_yellow("[!] Phase 2 OK but GNMAP missing.")
                except (FileNotFoundError, Exception) as e: print_yellow(f"[!] Phase 2 failed start/monitor: {e}") # Non-fatal
            if phase2_success and phase2_gnmap_content:
                 try: phase2_hosts = parse_gnmap_live_hosts(phase2_gnmap_content); print_green(f"    Extracted {len(phase2_hosts)} hosts 'Up'.")
                 except Exception as e: print_red(f"[!] Error parsing Phase 2 content: {e}")
            elif not phase2_success: log.info("Phase 2 failed/skipped, no hosts added.")
        else: print_yellow("[+] Skipping Phase 2 Ping Sweep.")

        # --- Determine Final Host List for Phase 3 ---
        print_blue("[+] Combining Hosts for Phase 3 Targeting")
        final_hosts_for_phase3 = sorted(list(phase1_hosts_passed_filter.union(phase2_hosts)))
        if final_hosts_for_phase3:
            try:
                with open(live_hosts_file, "w") as f: [f.write(host + "\n") for host in final_hosts_for_phase3]
                print_green(f"[+] {len(final_hosts_for_phase3)} hosts for Phase 3 -> {live_hosts_file.name}")
            except IOError as e: print_red(f"Error writing P3 target file: {e}"); sys.exit(1)
        else: print_red("[!] Warning: No hosts for Phase 3 & 4.")

        # --- Phase 3: Port Discovery (Still Blocking) ---
        phase3_completed = False; phase3_content = None
        if not final_hosts_for_phase3: print_red("[!] Skipping Phase 3: No targets.")
        elif args.phase3.lower() == 'skip': print_blue("[+] Phase 3: Skipped."); phase3_completed = False
        else:
            if not args.force_overwrite and phase3_xml_path.exists():
                 print_purple(f"[*] Phase 3: Output exists."); phase3_completed = True
                 try: phase3_content = phase3_gnmap_path.read_text(); print_green(f"    Using existing P3 results.")
                 except Exception as e: print_red(f"[!] Error reading existing P3 file: {e}"); phase3_completed = False
            else:
                try: phase3_nmap_opts = shlex.split(args.phase3)
                except ValueError as e: print_red(f"P3 opts error: {e}. Defaulting."); phase3_nmap_opts = ["-p-"]
                phase3_cmd_base = ["nmap", "-sS", "-Pn", "-n", "-T4", "--max-retries", "2", "--max-rtt-timeout", "500ms", "--host-timeout", "15m", "--max-scan-delay", "5ms", "--min-rate", "800", "-iL", str(live_hosts_file.resolve())]
                phase3_cmd_base.extend(phase3_nmap_opts); phase3_cmd_base.extend(["-oA", phase3_output_prefix])
                phase3_cmd = ["nmap", "-6"] + phase3_cmd_base[1:] if any(':' in ip for ip in final_hosts_for_phase3) else phase3_cmd_base
                try:
                    # Using original run_command here as we don't monitor P3 live yet
                    run_command(phase3_cmd, description=f"Phase 3: Port Discovery Scan ({args.phase3})") # Blocking call
                    phase3_completed = True
                    if phase3_gnmap_path.exists(): phase3_content = phase3_gnmap_path.read_text(); print_green(f"    Phase 3 scan completed.")
                    else: print_red("[!] Phase 3 OK but GNMAP missing!"); phase3_completed = False
                except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e: print_yellow(f"[!] Phase 3 failed/interrupted: {e}"); phase3_completed = False

        # --- Extract All Unique Open Ports ---
        # (Same as before)
        open_ports_list = []; gnmap_for_overall_ports_path = None; source_desc = "None"
        if phase3_completed and phase3_content: gnmap_for_overall_ports_path = phase3_gnmap_path; source_desc = "Phase 3"
        elif phase1_content: gnmap_for_overall_ports_path = phase1_gnmap_path; source_desc = "Phase 1"
        if gnmap_for_overall_ports_path:
            print_blue(f"[+] Extracting Overall Open Ports from {source_desc}")
            try: content = gnmap_for_overall_ports_path.read_text(); open_ports_list = parse_gnmap_all_open_ports(content)
            except Exception as e: print_red(f"[!] Error parsing {gnmap_for_overall_ports_path.name}: {e}")
        if open_ports_list:
            try: open_ports_file.write_text(",".join(map(str, open_ports_list)) + "\n"); print_green(f"    Saved {len(open_ports_list)} ports -> {open_ports_file.name}")
            except IOError as e: print_red(f"Error writing ports file: {e}")
        else: print_yellow(f"[!] No overall ports found in {source_desc}.")

        # --- Determine Hosts for Deep Scan ---
        # (Same as before)
        hosts_for_deep_scan = []; gnmap_content_for_deep_scan_ports = None; source_desc_p4 = "None"
        if phase3_completed and phase3_content: gnmap_content_for_deep_scan_ports = phase3_content; source_desc_p4 = "Phase 3"; print_blue("[+] Using P3 for Deep Scan ports.")
        elif phase1_content: gnmap_content_for_deep_scan_ports = phase1_content; source_desc_p4 = "Phase 1"; print_yellow("[!] Using P1 for Deep Scan ports.")
        else: print_red("[!] No usable content for Deep Scan.")
        if gnmap_content_for_deep_scan_ports and final_hosts_for_phase3:
             print_blue(f"[+] Identifying P4 targets from {len(final_hosts_for_phase3)} hosts using {source_desc_p4} data.")
             count_with_ports = 0
             for ip in final_hosts_for_phase3:
                  ports = parse_gnmap_ports_for_host(gnmap_content_for_deep_scan_ports, ip)
                  if ports: hosts_for_deep_scan.append(ip); count_with_ports += 1
             print_green(f"    Found {count_with_ports} hosts for P4.")
             if hosts_for_deep_scan:
                 try:
                     with open(hosts_for_deep_scan_file, "w") as f: [f.write(host + "\n") for host in hosts_for_deep_scan]
                     print_green(f"    P4 target list -> {hosts_for_deep_scan_file.name}")
                 except IOError as e: print_red(f"Error writing P4 target file: {e}")
             else: print_red("[!] No hosts for P4 after checking ports.")

        # --- Phase 4: Deep Scan (Simplified Progress) ---
        if not hosts_for_deep_scan: print_red("[!] Skipping Phase 4: No targets.")
        elif gnmap_content_for_deep_scan_ports is None: print_red("[!] Skipping Phase 4: Missing content.")
        else:
            print_blue(f"\n[+] Phase 4: Deep Scan on {len(hosts_for_deep_scan)} Hosts ({args.parallel_scans} threads)")
            scan_func = partial(run_deep_scan, scan_title_dir=current_scan_dir, gnmap_content_for_ports=gnmap_content_for_deep_scan_ports)
            results_summary = {'success': 0, 'skipped_exists': 0, 'skipped_no_ports': 0, 'warning_down': 0, 'failed': 0}
            completed_count = 0; total_tasks = len(hosts_for_deep_scan)
            phase4_start_time = time.time()

            with ThreadPoolExecutor(max_workers=args.parallel_scans) as executor:
                futures = {executor.submit(scan_func, ip): ip for ip in hosts_for_deep_scan}
                print_blue(f"    Submitted {total_tasks} jobs. Waiting...") # Simplified message

                for future in as_completed(futures):
                    ip = futures[future]; completed_count += 1
                    try:
                        target_ip, status_code = future.result()
                        if status_code in results_summary: results_summary[status_code] += 1
                        else: log.warning(f"Unknown status: {status_code}"); results_summary['failed'] += 1
                    except Exception as exc:
                        print_red(f'\n[!] Error processing P4 result for {ip}: {exc}')
                        log.exception(f"P4 future exception for {ip}")
                        results_summary['failed'] += 1

                    # Simple progress update
                    percentage = (completed_count / total_tasks) * 100
                    # Add spaces to clear previous line
                    sys.stdout.write(f"\r    Progress: {completed_count}/{total_tasks} ({percentage:.1f}%) completed. {' '*20}")
                    sys.stdout.flush()

            # Final newline and summary
            print() # Move to next line
            elapsed_phase4 = time.time() - phase4_start_time
            print_green(f"[+] Phase 4 complete. (Took {elapsed_phase4:.2f}s)")
            print_blue("    Summary:")
            print_green(f"      Success: {results_summary['success']}")
            print_purple(f"      Skipped (Exists): {results_summary['skipped_exists']}")
            print_yellow(f"      Skipped (No Ports): {results_summary['skipped_no_ports']}")
            print_yellow(f"      Warn (Host Down?): {results_summary['warning_down']}")
            print_red(f"      Failed: {results_summary['failed']}")

        # --- Final Output ---
        print_blue(f"\n--- Scan {args.scan_title} Complete ---")
        print_blue(f"--- Results are in: {current_scan_dir.resolve()} ---")

    finally:
        os.chdir(original_cwd)
        log.info(f"Changed back to: {original_cwd}")

if __name__ == "__main__":
    main()
