#!/usr/bin/env python3
#generated with Gemini based on a bash script i wrote. 

import argparse
import os
import subprocess
import sys
import re
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

log = None # Global logger instance

# --- Color Print Functions ---
def print_color(color, text):
    """Prints text in a specified color."""
    print(f"{color}{text}{Style.RESET_ALL}", flush=True)

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
    
    # Attempt to convert numeric defaults/inputs
    if isinstance(default, int):
        try: return int(value)
        except ValueError: print_red(f"Expected integer, got '{value}'. Using default '{default}'."); return default
    elif isinstance(default, str) and default.isdigit(): # Handle '1000' (str) default
        try: return int(value)
        except ValueError: return value # Keep as string if user input wasn't numeric
    return value

# --- Validation Functions ---
def is_valid_path(path_str):
    """Checks if a path is a readable file."""
    p = Path(path_str)
    return p.is_file() and os.access(p, os.R_OK)

def is_not_empty(value):
    """Checks if a value is not empty."""
    return bool(value)

def is_positive_int(value):
    """Checks if a value can be converted to a positive integer."""
    try: return int(value) > 0
    except ValueError: return False

def is_valid_phase3(value):
    """Basic validation for Phase 3 options (allows 'skip', nmap port specs)."""
    return bool(value) # Must not be empty

def is_yes_no(value):
    """Checks if a value is a 'yes' or 'no' variant."""
    return value.lower() in ['y', 'n', 'yes', 'no']

# --- Core Nmap Functions ---
def run_command(cmd_list, cwd=None, check=True, description="Running command"):
    """
    Runs a command using subprocess, logs output, and uses color.
    `cwd` should be an absolute path or None.
    Nmap's -oA argument should be an absolute path prefix or a simple filename if cwd is set.
    """
    global log
    cmd_str = shlex.join(cmd_list)
    print_blue(f"[+] {description}")
    print_yellow(f"    Command: {cmd_str}")
    
    # Ensure cwd is an absolute path string for subprocess and logging
    effective_cwd_path = Path(cwd).resolve() if cwd else Path.cwd()
    log.info(f"Running command: {cmd_str} in {effective_cwd_path}")

    try:
        process = subprocess.Popen(
            cmd_list, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            cwd=str(effective_cwd_path) # Popen expects string path
        )
        stdout, stderr = process.communicate()

        if stdout: log.debug(f"Command stdout:\n{stdout.strip()}")
        if stderr:
            if process.returncode != 0: log.error(f"Command stderr:\n{stderr.strip()}")
            else: log.warning(f"Command stderr (Return Code 0):\n{stderr.strip()}")

        if check and process.returncode != 0:
            log.error(f"Command failed with exit code {process.returncode}: {cmd_str}")
            error_details = f"Stderr:\n{stderr.strip()}" if stderr.strip() else "No stderr."
            log_file_path_msg = ""
            if log and log.handlers and hasattr(log.handlers[0], 'baseFilename'):
                log_file_path_msg = f"Check log: {Path(log.handlers[0].baseFilename).name}"
            else:
                log_file_path_msg = "Check console/log for details."
            print_red(f"    Command failed (Code: {process.returncode}). {log_file_path_msg}")
            raise subprocess.CalledProcessError(process.returncode, cmd_list, output=stdout, stderr=error_details)

        print_green(f"    Command completed successfully.")
        log.info(f"Command finished successfully: {cmd_str}")
        return stdout, stderr
    except FileNotFoundError:
        log.error(f"Error: Command not found: {cmd_list[0]}")
        print_red(f"    Error: Command {cmd_list[0]} not found. Is nmap installed and in PATH?")
        raise
    except Exception as e:
        log.exception(f"An unexpected error occurred while running command '{cmd_str}'")
        print_red(f"    An unexpected error occurred: {e}")
        raise

def parse_gnmap_live_hosts(gnmap_content):
    """Parses .gnmap content to find hosts marked as 'Up'."""
    global log
    live_hosts = set()
    # Pattern for hosts marked Up, handles optional hostname
    up_host_pattern = re.compile(r"^Host:\s+([\d.:a-fA-F]+)\s+(?:\(.*\)\s+)?Status:\s+Up", re.MULTILINE)
    for match in up_host_pattern.finditer(gnmap_content):
        ip = match.group(1); live_hosts.add(ip); log.debug(f"Found Up host: {ip}")
    log.info(f"Parsed gnmap. Found {len(live_hosts)} hosts marked 'Up'.")
    return live_hosts

def parse_gnmap_ports_for_host(gnmap_content, target_ip):
    """Parses .gnmap content for open or open|filtered ports for a specific host."""
    global log
    ports = set()
    # Regex: Host line for target_ip, then non-greedy match to 'Ports:', capture port details
    host_line_pattern = re.compile(
        r"^Host:\s+" + re.escape(target_ip) + r"\s*(?:\(.*\)\s*)?" # Match host IP, optional hostname
        r".*?\sPorts:\s+" # Non-greedy match until Ports:
        r"(.*)", # Capture port details string
        re.MULTILINE
    )
    port_pattern = re.compile(r"(\d+)/(?:open|open\|filtered)") # Match port/status
    match = host_line_pattern.search(gnmap_content)
    if match:
        ports_str = match.group(1); log.debug(f"Ports string for {target_ip}: {ports_str[:100]}...")
        found_ports = port_pattern.findall(ports_str); ports.update(found_ports)
        log.debug(f"Extracted open/open|filtered ports for {target_ip}: {ports}")
    else:
        log.debug(f"No 'Ports:' line with open ports for host {target_ip} in gnmap content.")
    return sorted([int(p) for p in ports])

def parse_gnmap_filter_no_open(gnmap_content, ignore_port=None):
    """
    Parses Phase 1 GNMAP. Returns IPs with at least one 'open' or 'open|filtered' port,
    excluding hosts where the *only* open port is `ignore_port`.
    """
    global log
    potentially_live_hosts = set()
    up_host_pattern = re.compile(r"^Host:\s+([\d.:a-fA-F]+)\s+(?:\(.*\)\s+)?Status:\s+Up", re.MULTILINE)
    log.debug(f"Starting Phase 1 style filter. Ignore Port: {ignore_port}")
    all_up_hosts = {match.group(1) for match in up_host_pattern.finditer(gnmap_content)}
    log.debug(f"Found {len(all_up_hosts)} 'Up' hosts in content for filtering.")

    for ip in all_up_hosts:
        open_ports = parse_gnmap_ports_for_host(gnmap_content, ip)
        if not open_ports: log.debug(f"Filtering host {ip}: No open/open|filtered ports."); continue
        if ignore_port is not None:
            try: ignore_port_int = int(ignore_port)
            except ValueError: log.error(f"Invalid ignore_port value '{ignore_port}', not an int."); ignore_port_int = -1 # Won't match
            if len(open_ports) == 1 and open_ports[0] == ignore_port_int:
                log.debug(f"Filtering host {ip}: Only ignored port {ignore_port} was open."); continue
        potentially_live_hosts.add(ip); log.debug(f"Keeping host {ip} (Ports: {open_ports}).")
    log.info(f"Phase 1 style filter complete. Kept {len(potentially_live_hosts)} hosts with relevant open ports.")
    return potentially_live_hosts

def parse_gnmap_all_open_ports(gnmap_content):
    """Parses .gnmap to find all unique open or open|filtered ports across all hosts."""
    port_pattern = re.compile(r"(\d+)/(?:open|open\|filtered)")
    ports = set(port_pattern.findall(gnmap_content))
    return sorted([int(p) for p in ports]) # Return sorted list of integers

def run_deep_scan(ip_to_scan, output_dir_path, sanitized_scan_title_as_prefix, gnmap_content_for_ports):
    """
    Task for running Phase 4 deep scan on a single IP.
    `output_dir_path` is the main scan directory (Path object).
    `sanitized_scan_title_as_prefix` is the sanitized scan_title from args.
    """
    global log
    ip_sanitized_for_filename = ip_to_scan.replace(':', '_').replace('.', '-') 
    
    # Construct filename for Phase 4: ScanTitle_phase4_DeepScan_HOST_IP.xml
    file_basename = f"{sanitized_scan_title_as_prefix}_phase4_DeepScan_HOST_{ip_sanitized_for_filename}"
    nmap_output_prefix_abs = output_dir_path / file_basename 
    xml_file_abs = nmap_output_prefix_abs.with_suffix(".xml")

    if xml_file_abs.exists(): 
        log.info(f"Deep scan for {ip_to_scan} (Scan: {sanitized_scan_title_as_prefix}) skipped: Output exists ({xml_file_abs.name})")
        return ip_to_scan, "skipped_exists", f"Skipped {ip_to_scan}: Output exists ({xml_file_abs.name})"

    ports_to_scan = parse_gnmap_ports_for_host(gnmap_content_for_ports, ip_to_scan)
    if not ports_to_scan:
        log.warning(f"Deep scan for {ip_to_scan} (Scan: {sanitized_scan_title_as_prefix}) called but no open ports. Skipping.")
        return ip_to_scan, "skipped_no_ports", f"Skipped {ip_to_scan}: No open ports in provided source"

    port_str = ",".join(map(str, ports_to_scan))
    log.info(f"Starting deep scan on {ip_to_scan} (Scan: {sanitized_scan_title_as_prefix}) (Ports: {port_str})")
    nmap_cmd_base = ["nmap", "-A", "-T4", "--max-retries", "3", "--max-rtt-timeout", "300ms", "--host-timeout", "8m", "-Pn", "-p", port_str, ip_to_scan, "-oA", str(nmap_output_prefix_abs)]
    nmap_cmd = ["nmap", "-6"] + nmap_cmd_base[1:] if ':' in ip_to_scan else nmap_cmd_base

    try:
        stdout, stderr = run_command(nmap_cmd, cwd=str(output_dir_path), check=True, description=f"Deep Scan {ip_to_scan} (Scan: {sanitized_scan_title_as_prefix})")
        if "Note: Host seems down" in stdout or "Failed to resolve" in stdout:
            log.warning(f"Deep scan for {ip_to_scan} completed but Nmap noted host seemed down/unresolved.")
            return ip_to_scan, "warning_down", f"Completed {ip_to_scan} with warning (host down?)"
        return ip_to_scan, "success", f"Completed {ip_to_scan}"
    except FileNotFoundError: return ip_to_scan, "failed", f"Failed {ip_to_scan}: Nmap not found"
    except subprocess.CalledProcessError as e: return ip_to_scan, "failed", f"Failed {ip_to_scan} (Code: {e.returncode})"
    except Exception as e: log.exception(f"Unexpected error during deep scan for {ip_to_scan}"); return ip_to_scan, "failed", f"Failed {ip_to_scan} (Error: {type(e).__name__})"


def process_single_target(target_subnet_or_ip, cli_args, main_output_dir_path, current_log_instance):
    """
    Processes a single target (subnet or IP) through all scanning phases.
    All Nmap output files are written to `main_output_dir_path`.
    `main_output_dir_path` is a Path object.
    Returns a dictionary with lists of IPs/ports for global aggregation.
    """
    global log
    log = current_log_instance 

    sanitized_target_name_prefix = re.sub(r'[^\w\-.]', '_', target_subnet_or_ip) 
    # Sanitize the overall scan_title for use in filenames
    sanitized_scan_title = re.sub(r'[^\w\-.]', '_', cli_args.scan_title)
    log.info(f"Processing target: {target_subnet_or_ip} (Subnet Prefix: {sanitized_target_name_prefix}). Scan Title Prefix: {sanitized_scan_title}. Output dir: {main_output_dir_path}")

    results_for_aggregation = {
        "phase3_target_ips": [], 
        "open_ports_found": set(), 
        "phase4_target_ips": [],
        "phase4_summary": {'success': 0, 'skipped_exists': 0, 'skipped_no_ports': 0, 'warning_down': 0, 'failed': 0}
    }

    # --- Phase 1: Discovery for this target ---
    phase1_file_basename = f"{sanitized_scan_title}_{sanitized_target_name_prefix}_phase1_Top{cli_args.top_ports}Ports"
    phase1_nmap_output_prefix_abs = main_output_dir_path / phase1_file_basename 
    phase1_gnmap_path_abs = main_output_dir_path / f"{phase1_file_basename}.gnmap"
    phase1_xml_path_abs = main_output_dir_path / f"{phase1_file_basename}.xml"
    phase1_content = None

    if not cli_args.force_overwrite and phase1_xml_path_abs.exists():
        print_purple(f"[*] Skipping Phase 1 for {target_subnet_or_ip}: Output {phase1_xml_path_abs.name} exists."); log.info(f"Skipping P1 for {target_subnet_or_ip}: {phase1_xml_path_abs.name} exists.")
        try: phase1_content = phase1_gnmap_path_abs.read_text(); log.info(f"Read existing P1 GNMAP for {target_subnet_or_ip} from {phase1_gnmap_path_abs.name}")
        except Exception as e: print_red(f"[!] Err reading existing P1 gnmap for {target_subnet_or_ip}: {e}"); log.error(f"Err read P1 {phase1_gnmap_path_abs}: {e}"); return None 
    else:
        phase1_cmd = ["nmap", "-sS", "-T4", "--max-retries", "1", "--max-rtt-timeout", "300ms", "--host-timeout", "3m", "--max-scan-delay", "5ms", "--min-rate", "800", "-Pn", "-n", target_subnet_or_ip, "--top-ports", str(cli_args.top_ports), "-oA", str(phase1_nmap_output_prefix_abs)]
        try:
            run_command(phase1_cmd, cwd=str(main_output_dir_path), description=f"Phase 1: Discovery for {target_subnet_or_ip}")
            if phase1_gnmap_path_abs.exists(): phase1_content = phase1_gnmap_path_abs.read_text()
            else: print_red(f"[!] P1 for {target_subnet_or_ip} completed but GNMAP output {phase1_gnmap_path_abs.name} not found!"); log.error(f"P1 GNMAP {phase1_gnmap_path_abs} missing post-scan."); return None
        except Exception as e: print_red(f"[!] P1 for {target_subnet_or_ip} failed: {e}"); log.error(f"P1 for {target_subnet_or_ip} failed: {e}"); return None
    
    if not phase1_content: print_red(f"[!] Critical: No P1 GNMAP content for {target_subnet_or_ip}. Skipping this target."); log.error(f"No P1 GNMAP content for {target_subnet_or_ip}."); return None

    log.info(f"Applying P1 Filter for {target_subnet_or_ip} (Ignore Port: {cli_args.ignore_port})")
    phase1_filtered_ips = parse_gnmap_filter_no_open(phase1_content, cli_args.ignore_port)
    print_green(f"    {len(phase1_filtered_ips)} IPs from {target_subnet_or_ip} passed P1 filtering."); log.info(f"{len(phase1_filtered_ips)} IPs from {target_subnet_or_ip} passed P1 filter. IPs: {list(phase1_filtered_ips)}")

    # --- Phase 2: Ping Sweep for this target ---
    phase2_live_ips = set()
    if not cli_args.skip_ping_sweep:
        # Filename: e.g. MyScan_192.168.1.0_24_phase2_PingSweep
        phase2_file_basename = f"{sanitized_scan_title}_{sanitized_target_name_prefix}_phase2_PingSweep"
        phase2_nmap_output_prefix_abs = main_output_dir_path / phase2_file_basename
        phase2_gnmap_path_abs = main_output_dir_path / f"{phase2_file_basename}.gnmap"
        phase2_xml_path_abs = main_output_dir_path / f"{phase2_file_basename}.xml" 
        phase2_gnmap_content = None

        if not cli_args.force_overwrite and phase2_xml_path_abs.exists():
            print_purple(f"[*] Skipping P2 for {target_subnet_or_ip}: Output {phase2_xml_path_abs.name} exists."); log.info(f"Skipping P2 for {target_subnet_or_ip}: {phase2_xml_path_abs.name} exists.")
            try: phase2_gnmap_content = phase2_gnmap_path_abs.read_text()
            except Exception as e: print_red(f"[!] Err reading existing P2 gnmap for {target_subnet_or_ip}: {e}"); log.warning(f"Could not read existing P2 gnmap {phase2_gnmap_path_abs}: {e}")
        else:
            phase2_cmd = ["nmap", "-sn", "-T4", "--max-retries", "1", "--max-rtt-timeout", "300ms", "--host-timeout", "5m", "-n", target_subnet_or_ip, "-oA", str(phase2_nmap_output_prefix_abs)]
            try:
                run_command(phase2_cmd, cwd=str(main_output_dir_path), description=f"Phase 2: Ping Sweep for {target_subnet_or_ip}")
                if phase2_gnmap_path_abs.exists(): phase2_gnmap_content = phase2_gnmap_path_abs.read_text()
                else: log.warning(f"P2 for {target_subnet_or_ip} ran but GNMAP output {phase2_gnmap_path_abs.name} not found.")
            except Exception as e: print_red(f"[!] P2 for {target_subnet_or_ip} failed: {e}"); log.error(f"P2 for {target_subnet_or_ip} failed: {e}") 
        
        if phase2_gnmap_content:
            try: 
                phase2_live_ips = parse_gnmap_live_hosts(phase2_gnmap_content)
                print_green(f"    Extracted {len(phase2_live_ips)} IPs marked 'Up' from P2 for {target_subnet_or_ip}.")
                log.info(f"Found {len(phase2_live_ips)} live IPs from P2 for {target_subnet_or_ip}: {list(phase2_live_ips)}")
            except Exception as e: print_red(f"[!] Err parsing P2 gnmap for {target_subnet_or_ip}: {e}"); log.error(f"Err parsing P2 gnmap for {target_subnet_or_ip}: {e}")
    else:
        print_yellow(f"[+] Skipping P2 Ping Sweep for {target_subnet_or_ip}."); log.info(f"Skipped P2 for {target_subnet_or_ip} by user.")

    ips_for_phase3_scan = sorted(list(phase1_filtered_ips.union(phase2_live_ips)))
    results_for_aggregation["phase3_target_ips"].extend(ips_for_phase3_scan) 

    if not ips_for_phase3_scan:
        print_red(f"[!] No live IPs from {target_subnet_or_ip} for P3. Skipping further phases for this target.")
        log.warning(f"No live IPs from {target_subnet_or_ip} for P3. P1_filtered: {len(phase1_filtered_ips)}, P2_live: {len(phase2_live_ips)}.")
        if phase1_content: results_for_aggregation["open_ports_found"].update(parse_gnmap_all_open_ports(phase1_content))
        return results_for_aggregation 

    print_green(f"    {len(ips_for_phase3_scan)} unique IPs from {target_subnet_or_ip} will be targeted in Phase 3."); log.info(f"{len(ips_for_phase3_scan)} IPs from {target_subnet_or_ip} for P3: {ips_for_phase3_scan}")

    # --- Phase 3: Port Discovery ---
    phase3_completed_successfully, phase3_content, phase3_input_host_list_file_abs = False, None, None
    if cli_args.phase3.lower() == 'skip':
        print_blue(f"[+] P3 for {target_subnet_or_ip}: Skipped by user request."); log.info(f"P3 skipped by user for IPs from {target_subnet_or_ip}.")
    else:
        phase3_opts_sanitized = re.sub(r'[^\w]', '', cli_args.phase3)[:15] 
        # Filename: e.g. MyScan_192.168.1.0_24_phase3_PortDisco_p--
        phase3_file_basename = f"{sanitized_scan_title}_{sanitized_target_name_prefix}_phase3_PortDisco_{phase3_opts_sanitized}"
        phase3_nmap_output_prefix_abs = main_output_dir_path / phase3_file_basename
        phase3_gnmap_path_abs = main_output_dir_path / f"{phase3_file_basename}.gnmap"
        phase3_xml_path_abs = main_output_dir_path / f"{phase3_file_basename}.xml" 

        if not cli_args.force_overwrite and phase3_xml_path_abs.exists():
            print_purple(f"[*] Skipping P3 Scan for IPs from {target_subnet_or_ip}: Output {phase3_xml_path_abs.name} exists."); log.info(f"Skipping P3 for IPs from {target_subnet_or_ip} as {phase3_xml_path_abs.name} exists.")
            phase3_completed_successfully = True
            try: phase3_content = phase3_gnmap_path_abs.read_text()
            except Exception as e: print_red(f"[!] Err reading existing P3 gnmap for {target_subnet_or_ip}: {e}"); log.error(f"Err reading existing P3 gnmap {phase3_gnmap_path_abs}: {e}"); phase3_completed_successfully = False
        else:
            try: phase3_nmap_opts_list = shlex.split(cli_args.phase3)
            except ValueError as e: log.warning(f"Error parsing P3 options '{cli_args.phase3}', using -p-. Error: {e}"); phase3_nmap_opts_list = ["-p-"]
            
            p3_cmd_list = ["nmap", "-sS", "-Pn", "-n", "-T4", "--max-retries", "2", "--max-rtt-timeout", "500ms", "--host-timeout", "15m", "--max-scan-delay", "5ms", "--min-rate", "800"]
            temp_p3_file_needed = False
            if len(ips_for_phase3_scan) == 1: 
                p3_cmd_list.append(ips_for_phase3_scan[0])
            elif len(ips_for_phase3_scan) > 1 : # Multiple IPs, use temporary -iL file
                phase3_input_host_list_file_abs = main_output_dir_path / f"{sanitized_scan_title}_{sanitized_target_name_prefix}_phase3_input_hosts.tmp"
                temp_p3_file_needed = True
                try:
                    with open(phase3_input_host_list_file_abs, "w") as f_tmp:
                        for ip_addr in ips_for_phase3_scan: f_tmp.write(ip_addr + "\n")
                    log.info(f"Created temp host list for P3 at {phase3_input_host_list_file_abs} with {len(ips_for_phase3_scan)} IPs.")
                    p3_cmd_list.extend(["-iL", str(phase3_input_host_list_file_abs)])
                except IOError as e_io:
                    log.error(f"Failed to write temp P3 host list {phase3_input_host_list_file_abs}: {e_io}. Skipping P3 for this target."); 
                    temp_p3_file_needed = False # Ensure it's not used if creation failed
            
            if not (("-iL" in p3_cmd_list and temp_p3_file_needed) or (len(ips_for_phase3_scan) == 1 and ips_for_phase3_scan[0] in p3_cmd_list)):
                 log.error(f"P3 command for {target_subnet_or_ip} does not have a valid target IP or -iL file. Skipping P3.")
            else: 
                p3_cmd_list.extend(phase3_nmap_opts_list)
                p3_cmd_list.extend(["-oA", str(phase3_nmap_output_prefix_abs)])
                final_p3_cmd = ["nmap", "-6"] + p3_cmd_list[1:] if any(':' in ip for ip in ips_for_phase3_scan) else p3_cmd_list
                try:
                    run_command(final_p3_cmd, cwd=str(main_output_dir_path), description=f"Phase 3: Port Discovery ({cli_args.phase3}) on {len(ips_for_phase3_scan)} IPs from {target_subnet_or_ip}")
                    phase3_completed_successfully = True
                    if phase3_gnmap_path_abs.exists(): phase3_content = phase3_gnmap_path_abs.read_text()
                    else: log.error(f"P3 GNMAP {phase3_gnmap_path_abs} not found for {target_subnet_or_ip} post-scan."); phase3_completed_successfully = False
                except Exception as e: log.error(f"P3 scan failed for IPs from {target_subnet_or_ip}: {e}"); phase3_completed_successfully = False
            
            if temp_p3_file_needed and phase3_input_host_list_file_abs and phase3_input_host_list_file_abs.exists():
                try: phase3_input_host_list_file_abs.unlink(); log.debug(f"Deleted temp P3 host list: {phase3_input_host_list_file_abs}")
                except OSError as e_del: log.warning(f"Could not delete temp P3 host list {phase3_input_host_list_file_abs}: {e_del}")

    gnmap_content_for_deep_scan_ports, source_desc_p4_ports = None, "None"
    if phase3_completed_successfully and phase3_content:
        gnmap_content_for_deep_scan_ports = phase3_content; source_desc_p4_ports = "Phase 3"
        log.info(f"Using Phase 3 results for {target_subnet_or_ip} to determine ports for its live IPs.")
    elif phase1_content: 
        gnmap_content_for_deep_scan_ports = phase1_content; source_desc_p4_ports = "Phase 1"
        log.warning(f"Phase 3 skipped or failed for {target_subnet_or_ip}. Using Phase 1 results for port details.")
    else: 
        print_red(f"[!] No usable .gnmap content (P1 or P3) for {target_subnet_or_ip}. Cannot determine ports for Deep Scan or global summary for this target.")
        log.error(f"No P1 or P3 gnmap content for {target_subnet_or_ip} for Phase 4 prep. This is unexpected if P1 succeeded.")
        return results_for_aggregation 

    if gnmap_content_for_deep_scan_ports:
        try:
            ports_from_target = parse_gnmap_all_open_ports(gnmap_content_for_deep_scan_ports)
            if ports_from_target: 
                results_for_aggregation["open_ports_found"].update(ports_from_target)
                log.info(f"Extracted {len(ports_from_target)} unique ports from {source_desc_p4_ports} results of {target_subnet_or_ip} for global summary.")
        except Exception as e:
            log.error(f"Error parsing {source_desc_p4_ports} gnmap for {target_subnet_or_ip} for port aggregation: {e}")

    ips_for_deep_scan_within_target = []
    if gnmap_content_for_deep_scan_ports and ips_for_phase3_scan: 
        log.info(f"Identifying which of {len(ips_for_phase3_scan)} IPs from {target_subnet_or_ip} have open ports in its {source_desc_p4_ports} results.")
        for ip_addr in ips_for_phase3_scan:
            ports = parse_gnmap_ports_for_host(gnmap_content_for_deep_scan_ports, ip_addr)
            if ports: ips_for_deep_scan_within_target.append(ip_addr)
            else: log.debug(f"IP {ip_addr} (from {target_subnet_or_ip}, targeted for P3) has no open ports listed in {source_desc_p4_ports}. Skipping for P4.")
        results_for_aggregation["phase4_target_ips"].extend(ips_for_deep_scan_within_target) 
        print_green(f"    Found {len(ips_for_deep_scan_within_target)} IPs from {target_subnet_or_ip} with open ports in {source_desc_p4_ports} results for Phase 4."); log.info(f"Identified {len(ips_for_deep_scan_within_target)} IPs from {target_subnet_or_ip} for P4 based on {source_desc_p4_ports} data: {ips_for_deep_scan_within_target}")

    # --- Phase 4: Deep Scan ---
    if not ips_for_deep_scan_within_target:
        print_red(f"[!] Skipping Phase 4 for {target_subnet_or_ip}: No target IPs with open ports identified from {source_desc_p4_ports} results.")
        log.warning(f"No IPs from {target_subnet_or_ip} for Phase 4 deep scan based on {source_desc_p4_ports} data.")
    elif gnmap_content_for_deep_scan_ports is None: 
        print_red(f"[!] Skipping Phase 4 for {target_subnet_or_ip}: Missing GNMAP content to determine ports."); log.error(f"Missing gnmap for P4 of {target_subnet_or_ip} (should be caught earlier).")
    else:
        print_blue(f"\n[+] Phase 4 for {target_subnet_or_ip}: Starting Deep Scan on {len(ips_for_deep_scan_within_target)} IPs (using {cli_args.parallel_scans} parallel threads)")
        log.info(f"Starting Phase 4 for {len(ips_for_deep_scan_within_target)} IPs from {target_subnet_or_ip}. Parallelism: {cli_args.parallel_scans}")
        
        # Pass the sanitized_scan_title to run_deep_scan for filename prefixing
        scan_func = partial(run_deep_scan, 
                            output_dir_path=main_output_dir_path, 
                            sanitized_scan_title_as_prefix=sanitized_scan_title, # Use overall sanitized scan title
                            gnmap_content_for_ports=gnmap_content_for_deep_scan_ports)
        
        p4_summary_this_target = {'success': 0, 'skipped_exists': 0, 'skipped_no_ports': 0, 'warning_down': 0, 'failed': 0}
        completed_count, total_tasks, phase4_start_time, progress_bar_length = 0, len(ips_for_deep_scan_within_target), time.time(), 40
        
        sys.stdout.write(f"    P4 Progress ({target_subnet_or_ip}): [{ ' ' * progress_bar_length }] 0% (0/{total_tasks})"); sys.stdout.flush()

        with ThreadPoolExecutor(max_workers=cli_args.parallel_scans) as executor:
            futures = {executor.submit(scan_func, ip): ip for ip in ips_for_deep_scan_within_target}
            for future in as_completed(futures):
                ip_addr = futures[future]
                completed_count += 1
                percentage = (completed_count / total_tasks) * 100
                filled_length = int(progress_bar_length * completed_count // total_tasks); bar = '#' * filled_length + ' ' * (progress_bar_length - filled_length)
                elapsed_time = time.time() - phase4_start_time; eta_str = ""
                if 0 < completed_count < total_tasks: est_total_time = (elapsed_time / completed_count) * total_tasks; eta = est_total_time - elapsed_time; eta_str = f" ETA: {int(eta//60)}m{int(eta%60)}s" if eta > 0 else ""
                
                current_progress_str = f"P4 Progress ({target_subnet_or_ip}): [{bar}] {percentage:.1f}% ({completed_count}/{total_tasks}){eta_str}"
                sys.stdout.write(f"\r    {current_progress_str} "); sys.stdout.flush() 
                
                try:
                    target_ip_processed, status_code, message = future.result() 
                    if status_code in p4_summary_this_target: p4_summary_this_target[status_code] += 1
                    else: p4_summary_this_target['failed'] += 1; log.warning(f"Unknown P4 status: {status_code} for {ip_addr}")

                    sys.stdout.write(f"\r{' ' * (len(current_progress_str) + 6)}\r") 
                    if status_code == "skipped_exists": print(f"    {Fore.MAGENTA}P4 Skipped (Exists): {ip_addr} (from {target_subnet_or_ip}){Style.RESET_ALL}")
                    elif status_code == "skipped_no_ports": print(f"    {Fore.YELLOW}P4 Skipped (No Ports): {ip_addr} (from {target_subnet_or_ip}){Style.RESET_ALL}")
                    elif status_code == "warning_down": print(f"    {Fore.YELLOW}P4 Warning (Down?): {ip_addr} (from {target_subnet_or_ip}){Style.RESET_ALL}")
                    elif status_code == "failed": print(f"    {Fore.RED}P4 FAILED: {message} ({ip_addr} from {target_subnet_or_ip}){Style.RESET_ALL}")
                    elif status_code == "success": log.info(f"P4 Success: {message} ({ip_addr} from {target_subnet_or_ip})") 
                    
                    if completed_count < total_tasks: 
                         sys.stdout.write(f"    {current_progress_str} ")
                         sys.stdout.flush()

                except Exception as exc:
                    sys.stdout.write(f"\r{' ' * (len(current_progress_str) + 6)}\r") 
                    print_red(f'\n    [!] IP {ip_addr} (from {target_subnet_or_ip}) generated P4 future exception: {exc}')
                    log.exception(f"P4 future exception for {ip_addr} from {target_subnet_or_ip}")
                    p4_summary_this_target['failed'] += 1
                    if completed_count < total_tasks: 
                        sys.stdout.write(f"    {current_progress_str} ")
                        sys.stdout.flush()
            print() 
        
        results_for_aggregation["phase4_summary"] = p4_summary_this_target
        log.info(f"Phase 4 for {target_subnet_or_ip} complete. Summary: {p4_summary_this_target}")
        print_blue(f"    Phase 4 Summary for {target_subnet_or_ip}:")
        for k, v_sum in p4_summary_this_target.items(): print(f"        {k.replace('_',' ').capitalize()}: {v_sum}")

    log.info(f"Finished processing target {target_subnet_or_ip}."); return results_for_aggregation


# --- Main Execution ---
def main():
    global log 

    parser = argparse.ArgumentParser(
        description="Perform a multi-phase network scan, processing each target from a list sequentially through all phases. All outputs to a single folder.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-s", "--scan-title", help="A unique name for this scan (used for main directory name and as a prefix in some global filenames).")
    parser.add_argument("-L", "--host-list", help="Path to the file containing target subnets/IPs (one per line).")
    parser.add_argument("-t", "--top-ports", type=int, default=1000, help="Number of top ports for Phase 1.")
    parser.add_argument("-i", "--ignore-port", type=int, default=None, metavar='PORT', help="Exclude hosts from Phase 3/4 if only this port is open in Phase 1.")
    parser.add_argument("--skip-ping-sweep", action="store_true", help="Skip the Phase 2 ping sweep.")
    parser.add_argument("--phase3", default="-p-", help="Phase 3 port spec ('-p-', '--top-ports X', 'skip', etc.).")
    parser.add_argument("-j", "--parallel-scans", type=int, default=35, help="Number of parallel deep scans (Phase 4) *per target subnet*.")
    parser.add_argument("-o", "--output-dir", default=".", help="Parent directory for scan results (the --scan-title folder will be created here).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")
    parser.add_argument("-f", "--force-overwrite", action="store_true", help="Force re-running scans even if output files exist (applies per phase file).")
    args = parser.parse_args()

    try:
        if os.name == 'posix' and os.geteuid() != 0:
            print_yellow("Warning: This script may require root privileges (or sudo) for certain Nmap scan types (e.g., -sS SYN scans). Continuing without root...")
    except AttributeError: 
        print_yellow("Warning: Could not check for root privileges on this OS. Some Nmap scans might fail if not run as administrator/root.")

    print_blue("--- Scan Configuration ---")
    if args.scan_title is None: args.scan_title = prompt_user("Enter a unique scan title:", validation_func=is_not_empty)
    else: print(f"Scan Title: {args.scan_title}")

    if args.host_list is None: args.host_list = prompt_user("Enter path to host list file:", validation_func=is_valid_path)
    elif not is_valid_path(args.host_list): 
        print_red(f"Error: Host list file from argument not found: {args.host_list}")
        args.host_list = prompt_user("Re-enter path to host list file:", validation_func=is_valid_path)
    else: print(f"Host List: {args.host_list}")
    host_file_path = Path(args.host_list)

    args.top_ports = prompt_user(f"Top ports for Phase 1 host discovery:", default=args.top_ports, validation_func=is_positive_int)
    ignore_port_input = input(f"Port to ignore if solo in Phase 1 (blank for none) [{args.ignore_port or 'None'}]: ").strip()
    if ignore_port_input:
        try: args.ignore_port = int(ignore_port_input)
        except ValueError: print_red("Invalid ignore port. No port will be ignored."); args.ignore_port = None
    
    skip_ping_default = 'Y' if args.skip_ping_sweep else 'N' 
    args.skip_ping_sweep = prompt_user("Skip Phase 2 Ping Sweep and use Phase 1 results? (y/N)", default=skip_ping_default, validation_func=is_yes_no).lower().startswith('y')
    
    args.phase3 = prompt_user(f"Phase 3 port discovery: '-p-' (all), '--top-ports X', 'T:1-65535', 'skip' to use Phase 1 results:", default=args.phase3, validation_func=is_valid_phase3)
    args.parallel_scans = prompt_user(f"Parallel deep scans (Phase 4) per subnet:", default=args.parallel_scans, validation_func=is_positive_int)
    print(f"Base output directory for results: {Path(args.output_dir).resolve()}")
    print(f"Force overwrite existing files: {'Yes' if args.force_overwrite else 'No'}")

    main_scan_output_dir = Path(args.output_dir).resolve() / args.scan_title
    try:
        main_scan_output_dir.mkdir(parents=True, exist_ok=True)
        print(f"{Fore.BLUE}Main output directory for all files: {main_scan_output_dir}{Style.RESET_ALL}")
    except OSError as e:
        print_red(f"Error creating main output directory {main_scan_output_dir}: {e}"); sys.exit(1)

    log_file_path = main_scan_output_dir / f"{args.scan_title}_main_scan.log" # Global summary files also use args.scan_title
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_format = '%(asctime)s - %(levelname)s - [%(name)s] - %(module)s.%(funcName)s:%(lineno)d - %(message)s'
    logging.basicConfig(level=log_level, format=log_format, filename=log_file_path, filemode='a', force=True)
    log = logging.getLogger("PerTargetPhaseScanner") 
    log.info(f"--- Logging started. Level: {logging.getLevelName(log_level)}. Output File: {log_file_path.name} ---")
    log.info(f"Scan Title: {args.scan_title}, Host List File: {host_file_path.resolve()}")
    log.info(f"Effective CLI Arguments: {args}")

    print_yellow(f"\n--- Starting Scan Campaign: {args.scan_title} ---")
    print_yellow(f"--- Target List File: {host_file_path.resolve()} ---")
    print_yellow(f"--- All Output To: {main_scan_output_dir.resolve()} ---")
    time.sleep(1) 

    targets_to_process = []
    try:
        with open(host_file_path, "r") as f:
            targets_to_process = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        if not targets_to_process:
            print_red(f"No targets found in {host_file_path.resolve()}. Exiting.")
            log.error(f"No targets found in host list file: {host_file_path.resolve()}.")
            sys.exit(1)
        log.info(f"Read {len(targets_to_process)} targets/subnets from {host_file_path.resolve()}: {targets_to_process}")
    except IOError as e:
        print_red(f"Error reading host file {host_file_path.resolve()}: {e}")
        log.critical(f"Cannot read host file {host_file_path.resolve()}: {e}"); sys.exit(1)

    overall_phase3_target_hosts_agg = []
    overall_open_ports_agg = set()
    overall_phase4_target_hosts_agg = [] 
    phase4_results_summary_global_agg = {'success': 0, 'skipped_exists': 0, 'skipped_no_ports': 0, 'warning_down': 0, 'failed': 0}
    
    total_subnets_in_list = len(targets_to_process)
    subnets_successfully_processed_all_phases = 0

    for i, current_target_subnet_or_ip in enumerate(targets_to_process):
        print_purple(f"\n--- Processing Target {i+1}/{total_subnets_in_list}: {current_target_subnet_or_ip} ---")
        log.info(f"--- Starting processing for target {i+1}/{total_subnets_in_list}: {current_target_subnet_or_ip} ---")

        target_processing_results = process_single_target(
            current_target_subnet_or_ip,
            args,
            main_scan_output_dir, 
            log 
        )

        if target_processing_results:
            subnets_successfully_processed_all_phases +=1 
            overall_phase3_target_hosts_agg.extend(target_processing_results.get("phase3_target_ips", []))
            overall_open_ports_agg.update(target_processing_results.get("open_ports_found", set()))
            overall_phase4_target_hosts_agg.extend(target_processing_results.get("phase4_target_ips", []))
            
            p4_summary_for_target = target_processing_results.get("phase4_summary", {})
            for key in phase4_results_summary_global_agg: 
                phase4_results_summary_global_agg[key] += p4_summary_for_target.get(key, 0)
            
            log.info(f"--- Finished processing and aggregated results for target: {current_target_subnet_or_ip} ---")
            print_green(f"--- Successfully completed processing for target: {current_target_subnet_or_ip} ---")
        else:
            log.warning(f"--- Processing FAILED or returned no results for target: {current_target_subnet_or_ip}. Check logs for details. ---")
            print_red(f"--- Processing FAILED for target: {current_target_subnet_or_ip}. Check log: {log_file_path.name} ---")
        
        progress_percentage = ((i + 1) / total_subnets_in_list) * 100
        print_blue(f"=== Overall Target Progress: {i+1}/{total_subnets_in_list} targets initiated ({progress_percentage:.1f}%). {subnets_successfully_processed_all_phases} successfully completed processing. ===")


    print_blue("\n--- Generating Global Summary Files ---")
    log.info("Generating global summary files.")

    if overall_phase3_target_hosts_agg:
        unique_overall_p3_hosts = sorted(list(set(overall_phase3_target_hosts_agg)))
        g_p3_file = main_scan_output_dir / f"{args.scan_title}_ALL_phase3_target_hosts.txt" # Uses scan_title from args
        try:
            with open(g_p3_file, "w") as f: f.write("\n".join(unique_overall_p3_hosts) + "\n")
            print_green(f"[+] {len(unique_overall_p3_hosts)} unique hosts targeted for P3 (globally) saved to {g_p3_file.name}")
            log.info(f"Saved {len(unique_overall_p3_hosts)} global P3 target hosts to {g_p3_file.name}")
        except IOError as e: print_red(f"Error writing global P3 hosts file {g_p3_file.name}: {e}"); log.error(f"Err writing global P3 file: {e}")
    else: print_yellow("[!] No hosts were targeted for Phase 3 globally."); log.info("No global P3 target hosts.")

    if overall_open_ports_agg:
        sorted_ports_globally = sorted([int(p) for p in overall_open_ports_agg])
        g_ports_file = main_scan_output_dir / f"{args.scan_title}_ALL_open_ports.txt" # Uses scan_title from args
        try:
            g_ports_file.write_text(",".join(map(str, sorted_ports_globally)) + "\n")
            print_green(f"[+] All {len(sorted_ports_globally)} unique open ports (globally) saved to {g_ports_file.name}")
            log.info(f"Saved {len(sorted_ports_globally)} global open ports to {g_ports_file.name}")
        except IOError as e: print_red(f"Error writing global ports file {g_ports_file.name}: {e}"); log.error(f"Err writing global ports file: {e}")
    else: print_yellow("[!] No open ports found globally across all targets."); log.info("No global open ports found.")

    if overall_phase4_target_hosts_agg: 
        unique_overall_p4_hosts = sorted(list(set(overall_phase4_target_hosts_agg)))
        g_p4_file = main_scan_output_dir / f"{args.scan_title}_ALL_phase4_target_hosts.txt" # Uses scan_title from args
        try:
            with open(g_p4_file, "w") as f: f.write("\n".join(unique_overall_p4_hosts) + "\n")
            print_green(f"[+] {len(unique_overall_p4_hosts)} unique hosts targeted for P4 Deep Scan (globally) saved to {g_p4_file.name}")
            log.info(f"Saved {len(unique_overall_p4_hosts)} global P4 target hosts to {g_p4_file.name}")
        except IOError as e: print_red(f"Error writing global P4 hosts file {g_p4_file.name}: {e}"); log.error(f"Err writing global P4 file: {e}")
    else: print_yellow("[!] No hosts were targeted for Phase 4 Deep Scan globally."); log.info("No global P4 target hosts.")

    print_blue("\n[+] Global Phase 4 Deep Scan Summary (across all targets):")
    if sum(phase4_results_summary_global_agg.values()) > 0:
        for k_sum, v_sum in phase4_results_summary_global_agg.items(): print_green(f"    {k_sum.replace('_',' ').capitalize()}: {v_sum}")
        log.info(f"Global Phase 4 Summary: {phase4_results_summary_global_agg}")
    else: print_yellow("    No Phase 4 deep scans were initiated globally (or all failed before summary)."); log.info("No P4 scans initiated/summarized globally.")

    print_blue(f"\n--- Scan Campaign {args.scan_title} Complete ---")
    print_blue(f"--- All results are in: {main_scan_output_dir.resolve()} ---")
    print_blue(f"--- Main log file: {log_file_path.resolve()} ---")
    log.info(f"--- Scan Campaign {args.scan_title} Complete ---")
    
    logging.shutdown()

if __name__ == "__main__":
    main()
