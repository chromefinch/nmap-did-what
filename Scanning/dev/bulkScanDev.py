#!/usr/bin/env python3
#AI slop baby!
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
import ipaddress # Added for CIDR manipulation

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
    
    if isinstance(default, int):
        try: return int(value)
        except ValueError: print_red(f"Expected integer, got '{value}'. Using default '{default}'."); return default
    elif isinstance(default, str) and default.isdigit(): 
        try: return int(value)
        except ValueError: return value 
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
    """Basic validation for Phase 3 options."""
    return bool(value) 

def is_yes_no(value):
    """Checks if a value is a 'yes' or 'no' variant."""
    return value.lower() in ['y', 'n', 'yes', 'no']

def is_valid_cidr(cidr_str):
    """Checks if a string is a valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False

# --- Core Nmap/Masscan Functions ---
def run_external_command(cmd_list, cwd=None, check_return_code=True, description="Running command"):
    """
    Runs an external command (like nmap or masscan).
    Returns tuple (command_attempted_bool, success_bool_based_on_check, stdout_str, stderr_str).
    'success_bool_based_on_check' is True if check_return_code is True and return code is 0.
    'command_attempted_bool' is True if the command was found and Popen succeeded.
    """
    global log
    cmd_str = shlex.join(cmd_list)
    print_blue(f"[+] {description}")
    print_yellow(f"    Command: {cmd_str}")
    
    effective_cwd_path = Path(cwd).resolve() if cwd else Path.cwd()
    log.info(f"Running command: {cmd_str} in {effective_cwd_path}")

    command_attempted = False
    operation_successful = False # Based on check_return_code

    try:
        process = subprocess.Popen(
            cmd_list, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            cwd=str(effective_cwd_path)
        )
        command_attempted = True # Popen succeeded
        stdout, stderr = process.communicate()

        if stdout: log.debug(f"Command stdout:\n{stdout.strip()}")
        if stderr:
            if process.returncode != 0 or "ERROR" in stderr.upper() or "FAIL" in stderr.upper():
                 log.error(f"Command stderr:\n{stderr.strip()}")
            else:
                 log.debug(f"Command stderr (may be status info):\n{stderr.strip()}")

        if check_return_code:
            if process.returncode == 0:
                operation_successful = True
                print_green(f"    Command completed successfully (exit 0).")
                log.info(f"Command finished successfully (exit 0): {cmd_str}")
            else:
                operation_successful = False
                log.error(f"Command failed with exit code {process.returncode}: {cmd_str}")
                log_file_path_msg = f"Check log: {Path(log.handlers[0].baseFilename).name}" if log and log.handlers and hasattr(log.handlers[0], 'baseFilename') else "Check console/log."
                print_red(f"    Command failed (Code: {process.returncode}). {log_file_path_msg}")
        else: # Not checking return code for operational success, but command did run
            operation_successful = True # Assume operationally "successful" in the sense it ran
            print_green(f"    Command run (return code not checked for operational success). Exit code: {process.returncode}")
            log.info(f"Command run (return code not primary success indicator): {cmd_str}. Exit code: {process.returncode}")

        return command_attempted, operation_successful, stdout, stderr

    except FileNotFoundError:
        log.error(f"Error: Command not found: {cmd_list[0]}")
        print_red(f"    Error: Command {cmd_list[0]} not found. Is it installed and in PATH?")
        return False, False, "", f"Command not found: {cmd_list[0]}"
    except Exception as e:
        log.exception(f"An unexpected error occurred while running command '{cmd_str}'")
        print_red(f"    An unexpected error occurred: {e}")
        return False, False, "", str(e)


def parse_gnmap_live_hosts(gnmap_content):
    """Parses .gnmap content to find hosts marked as 'Up'."""
    global log
    live_hosts = set()
    up_host_pattern = re.compile(r"^Host:\s+([\d.:a-fA-F]+)\s+(?:\(.*\)\s+)?Status:\s+Up", re.MULTILINE)
    for match in up_host_pattern.finditer(gnmap_content):
        ip = match.group(1); live_hosts.add(ip); log.debug(f"Found Up host: {ip}")
    log.info(f"Parsed gnmap. Found {len(live_hosts)} hosts marked 'Up'.")
    return live_hosts

def parse_gnmap_ports_for_host(gnmap_content, target_ip):
    """Parses .gnmap content for open or open|filtered ports for a specific host."""
    global log
    ports = set()
    host_line_pattern = re.compile(
        r"^Host:\s+" + re.escape(target_ip) + r"\s*(?:\(.*\)\s*)?" 
        r".*?\sPorts:\s+" 
        r"(.*)", 
        re.MULTILINE
    )
    port_pattern = re.compile(r"(\d+)/(?:open|open\|filtered)") 
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
            except ValueError: log.error(f"Invalid ignore_port value '{ignore_port}', not an int."); ignore_port_int = -1 
            if len(open_ports) == 1 and open_ports[0] == ignore_port_int:
                log.debug(f"Filtering host {ip}: Only ignored port {ignore_port} was open."); continue
        potentially_live_hosts.add(ip); log.debug(f"Keeping host {ip} (Ports: {open_ports}).")
    log.info(f"Phase 1 style filter complete. Kept {len(potentially_live_hosts)} hosts with relevant open ports.")
    return potentially_live_hosts

def parse_gnmap_all_open_ports(gnmap_content):
    """Parses .gnmap to find all unique open or open|filtered ports across all hosts."""
    port_pattern = re.compile(r"(\d+)/(?:open|open\|filtered)")
    ports = set(port_pattern.findall(gnmap_content))
    return sorted([int(p) for p in ports]) 

def run_deep_scan(ip_to_scan, output_dir_path, sanitized_scan_title_as_prefix, gnmap_content_for_ports):
    """
    Task for running Phase 4 deep scan on a single IP.
    `sanitized_scan_title_as_prefix` is the sanitized scan_title from args.
    """
    global log
    ip_sanitized_for_filename = ip_to_scan.replace(':', '_').replace('.', '-') 
    
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

    _, success, stdout, stderr = run_external_command(nmap_cmd, cwd=str(output_dir_path), check_return_code=True, description=f"Deep Scan {ip_to_scan} (Scan: {sanitized_scan_title_as_prefix})")
    
    if not success:
        if "Command not found" in stderr:
             return ip_to_scan, "failed", f"Failed {ip_to_scan}: Nmap not found"
        return ip_to_scan, "failed", f"Failed {ip_to_scan} (Check logs for error code)"

    if "Note: Host seems down" in stdout or "Failed to resolve" in stdout: 
        log.warning(f"Deep scan for {ip_to_scan} completed but Nmap noted host seemed down/unresolved.")
        return ip_to_scan, "warning_down", f"Completed {ip_to_scan} with warning (host down?)"
    return ip_to_scan, "success", f"Completed {ip_to_scan}"


def process_single_target(target_subnet_or_ip, cli_args, main_output_dir_path, current_log_instance):
    """
    Processes a single target (subnet or IP) through Nmap scanning phases.
    """
    global log
    log = current_log_instance 

    sanitized_target_name_prefix = re.sub(r'[^\w\-.]', '_', target_subnet_or_ip) 
    sanitized_scan_title = re.sub(r'[^\w\-.]', '_', cli_args.scan_title)
    log.info(f"Processing Nmap phases for target: {target_subnet_or_ip} (Subnet Prefix: {sanitized_target_name_prefix}). Scan Title Prefix: {sanitized_scan_title}. Output dir: {main_output_dir_path}")

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
        print_purple(f"[*] Skipping Nmap Phase 1 for {target_subnet_or_ip}: Output {phase1_xml_path_abs.name} exists."); log.info(f"Skipping Nmap P1 for {target_subnet_or_ip}: {phase1_xml_path_abs.name} exists.")
        try: phase1_content = phase1_gnmap_path_abs.read_text(); log.info(f"Read existing Nmap P1 GNMAP for {target_subnet_or_ip} from {phase1_gnmap_path_abs.name}")
        except Exception as e: print_red(f"[!] Err reading existing Nmap P1 gnmap for {target_subnet_or_ip}: {e}"); log.error(f"Err read Nmap P1 {phase1_gnmap_path_abs}: {e}"); return None 
    else:
        phase1_cmd = ["nmap", "-sS", "-T4", "--max-retries", "1", "--max-rtt-timeout", "300ms", "--host-timeout", "3m", "--max-scan-delay", "5ms", "--min-rate", "800", "-Pn", "-n", target_subnet_or_ip, "--top-ports", str(cli_args.top_ports), "-oA", str(phase1_nmap_output_prefix_abs)]
        _, success, _, _ = run_external_command(phase1_cmd, cwd=str(main_output_dir_path), check_return_code=True, description=f"Nmap Phase 1: Discovery for {target_subnet_or_ip}")
        if success:
            if phase1_gnmap_path_abs.exists(): phase1_content = phase1_gnmap_path_abs.read_text()
            else: print_red(f"[!] Nmap P1 for {target_subnet_or_ip} completed but GNMAP output {phase1_gnmap_path_abs.name} not found!"); log.error(f"Nmap P1 GNMAP {phase1_gnmap_path_abs} missing post-scan."); return None
        else:
            print_red(f"[!] Nmap P1 for {target_subnet_or_ip} failed."); log.error(f"Nmap P1 for {target_subnet_or_ip} failed."); return None
    
    if not phase1_content: print_red(f"[!] Critical: No Nmap P1 GNMAP content for {target_subnet_or_ip}. Skipping this target."); log.error(f"No Nmap P1 GNMAP content for {target_subnet_or_ip}."); return None

    log.info(f"Applying Nmap P1 Filter for {target_subnet_or_ip} (Ignore Port: {cli_args.ignore_port})")
    phase1_filtered_ips = parse_gnmap_filter_no_open(phase1_content, cli_args.ignore_port)
    print_green(f"    {len(phase1_filtered_ips)} IPs from {target_subnet_or_ip} passed Nmap P1 filtering."); log.info(f"{len(phase1_filtered_ips)} IPs from {target_subnet_or_ip} passed Nmap P1 filter. IPs: {list(phase1_filtered_ips)}")

    # --- Phase 2: Ping Sweep for this target ---
    phase2_live_ips = set()
    if not cli_args.skip_ping_sweep:
        phase2_file_basename = f"{sanitized_scan_title}_{sanitized_target_name_prefix}_phase2_PingSweep"
        phase2_nmap_output_prefix_abs = main_output_dir_path / phase2_file_basename
        phase2_gnmap_path_abs = main_output_dir_path / f"{phase2_file_basename}.gnmap"
        phase2_xml_path_abs = main_output_dir_path / f"{phase2_file_basename}.xml" 
        phase2_gnmap_content = None

        if not cli_args.force_overwrite and phase2_xml_path_abs.exists():
            print_purple(f"[*] Skipping Nmap P2 for {target_subnet_or_ip}: Output {phase2_xml_path_abs.name} exists."); log.info(f"Skipping Nmap P2 for {target_subnet_or_ip}: {phase2_xml_path_abs.name} exists.")
            try: phase2_gnmap_content = phase2_gnmap_path_abs.read_text()
            except Exception as e: print_red(f"[!] Err reading existing Nmap P2 gnmap for {target_subnet_or_ip}: {e}"); log.warning(f"Could not read existing Nmap P2 gnmap {phase2_gnmap_path_abs}: {e}")
        else:
            phase2_cmd = ["nmap", "-sn", "-T4", "--max-retries", "1", "--max-rtt-timeout", "300ms", "--host-timeout", "5m", "-n", target_subnet_or_ip, "-oA", str(phase2_nmap_output_prefix_abs)]
            _, success, _, _ = run_external_command(phase2_cmd, cwd=str(main_output_dir_path), check_return_code=True, description=f"Nmap Phase 2: Ping Sweep for {target_subnet_or_ip}")
            if success:
                if phase2_gnmap_path_abs.exists(): phase2_gnmap_content = phase2_gnmap_path_abs.read_text()
                else: log.warning(f"Nmap P2 for {target_subnet_or_ip} ran but GNMAP output {phase2_gnmap_path_abs.name} not found.")
            else:
                 print_red(f"[!] Nmap P2 for {target_subnet_or_ip} failed."); log.error(f"Nmap P2 for {target_subnet_or_ip} failed.")
        
        if phase2_gnmap_content:
            try: 
                phase2_live_ips = parse_gnmap_live_hosts(phase2_gnmap_content)
                print_green(f"    Extracted {len(phase2_live_ips)} IPs marked 'Up' from Nmap P2 for {target_subnet_or_ip}.")
                log.info(f"Found {len(phase2_live_ips)} live IPs from Nmap P2 for {target_subnet_or_ip}: {list(phase2_live_ips)}")
            except Exception as e: print_red(f"[!] Err parsing Nmap P2 gnmap for {target_subnet_or_ip}: {e}"); log.error(f"Err parsing Nmap P2 gnmap for {target_subnet_or_ip}: {e}")
    else:
        print_yellow(f"[+] Skipping Nmap P2 Ping Sweep for {target_subnet_or_ip}."); log.info(f"Skipped Nmap P2 for {target_subnet_or_ip} by user.")

    ips_for_phase3_scan = sorted(list(phase1_filtered_ips.union(phase2_live_ips)))
    results_for_aggregation["phase3_target_ips"].extend(ips_for_phase3_scan) 

    if not ips_for_phase3_scan:
        print_red(f"[!] No live IPs from {target_subnet_or_ip} for Nmap P3. Skipping further Nmap phases for this target.")
        log.warning(f"No live IPs from {target_subnet_or_ip} for Nmap P3. P1_filtered: {len(phase1_filtered_ips)}, P2_live: {len(phase2_live_ips)}.")
        if phase1_content: results_for_aggregation["open_ports_found"].update(parse_gnmap_all_open_ports(phase1_content))
        return results_for_aggregation 

    print_green(f"    {len(ips_for_phase3_scan)} unique IPs from {target_subnet_or_ip} will be targeted in Nmap Phase 3."); log.info(f"{len(ips_for_phase3_scan)} IPs from {target_subnet_or_ip} for Nmap P3: {ips_for_phase3_scan}")

    # --- Phase 3: Port Discovery ---
    phase3_completed_successfully, phase3_content, phase3_input_host_list_file_abs = False, None, None
    if cli_args.phase3.lower() == 'skip':
        print_blue(f"[+] Nmap P3 for {target_subnet_or_ip}: Skipped by user request."); log.info(f"Nmap P3 skipped by user for IPs from {target_subnet_or_ip}.")
    else:
        phase3_opts_sanitized = re.sub(r'[^\w]', '', cli_args.phase3)[:15] 
        phase3_file_basename = f"{sanitized_scan_title}_{sanitized_target_name_prefix}_phase3_PortDisco_{phase3_opts_sanitized}"
        phase3_nmap_output_prefix_abs = main_output_dir_path / phase3_file_basename
        phase3_gnmap_path_abs = main_output_dir_path / f"{phase3_file_basename}.gnmap"
        phase3_xml_path_abs = main_output_dir_path / f"{phase3_file_basename}.xml" 

        if not cli_args.force_overwrite and phase3_xml_path_abs.exists():
            print_purple(f"[*] Skipping Nmap P3 Scan for IPs from {target_subnet_or_ip}: Output {phase3_xml_path_abs.name} exists."); log.info(f"Skipping Nmap P3 for IPs from {target_subnet_or_ip} as {phase3_xml_path_abs.name} exists.")
            phase3_completed_successfully = True
            try: phase3_content = phase3_gnmap_path_abs.read_text()
            except Exception as e: print_red(f"[!] Err reading existing Nmap P3 gnmap for {target_subnet_or_ip}: {e}"); log.error(f"Err reading existing Nmap P3 gnmap {phase3_gnmap_path_abs}: {e}"); phase3_completed_successfully = False
        else:
            try: phase3_nmap_opts_list = shlex.split(cli_args.phase3)
            except ValueError as e: log.warning(f"Error parsing Nmap P3 options '{cli_args.phase3}', using -p-. Error: {e}"); phase3_nmap_opts_list = ["-p-"]
            
            p3_cmd_list = ["nmap", "-sS", "-Pn", "-n", "-T4", "--max-retries", "2", "--max-rtt-timeout", "500ms", "--host-timeout", "15m", "--max-scan-delay", "5ms", "--min-rate", "800"]
            temp_p3_file_needed = False
            if len(ips_for_phase3_scan) == 1: 
                p3_cmd_list.append(ips_for_phase3_scan[0])
            elif len(ips_for_phase3_scan) > 1 : 
                phase3_input_host_list_file_abs = main_output_dir_path / f"{sanitized_scan_title}_{sanitized_target_name_prefix}_phase3_input_hosts.tmp"
                temp_p3_file_needed = True
                try:
                    with open(phase3_input_host_list_file_abs, "w") as f_tmp:
                        for ip_addr in ips_for_phase3_scan: f_tmp.write(ip_addr + "\n")
                    log.info(f"Created temp host list for Nmap P3 at {phase3_input_host_list_file_abs} with {len(ips_for_phase3_scan)} IPs.")
                    p3_cmd_list.extend(["-iL", str(phase3_input_host_list_file_abs)])
                except IOError as e_io:
                    log.error(f"Failed to write temp Nmap P3 host list {phase3_input_host_list_file_abs}: {e_io}. Skipping Nmap P3 for this target."); 
                    temp_p3_file_needed = False 
            
            if not (("-iL" in p3_cmd_list and temp_p3_file_needed) or (len(ips_for_phase3_scan) == 1 and ips_for_phase3_scan[0] in p3_cmd_list)):
                 log.error(f"Nmap P3 command for {target_subnet_or_ip} does not have a valid target IP or -iL file. Skipping Nmap P3.")
            else: 
                p3_cmd_list.extend(phase3_nmap_opts_list)
                p3_cmd_list.extend(["-oA", str(phase3_nmap_output_prefix_abs)])
                final_p3_cmd = ["nmap", "-6"] + p3_cmd_list[1:] if any(':' in ip for ip in ips_for_phase3_scan) else p3_cmd_list
                _, success, _, _ = run_external_command(final_p3_cmd, cwd=str(main_output_dir_path), check_return_code=True, description=f"Nmap Phase 3: Port Discovery ({cli_args.phase3}) on {len(ips_for_phase3_scan)} IPs from {target_subnet_or_ip}")
                if success:
                    phase3_completed_successfully = True
                    if phase3_gnmap_path_abs.exists(): phase3_content = phase3_gnmap_path_abs.read_text()
                    else: log.error(f"Nmap P3 GNMAP {phase3_gnmap_path_abs} not found for {target_subnet_or_ip} post-scan."); phase3_completed_successfully = False
                else:
                    log.error(f"Nmap P3 scan failed for IPs from {target_subnet_or_ip}."); phase3_completed_successfully = False
            
            if temp_p3_file_needed and phase3_input_host_list_file_abs and phase3_input_host_list_file_abs.exists():
                try: phase3_input_host_list_file_abs.unlink(); log.debug(f"Deleted temp Nmap P3 host list: {phase3_input_host_list_file_abs}")
                except OSError as e_del: log.warning(f"Could not delete temp Nmap P3 host list {phase3_input_host_list_file_abs}: {e_del}")

    gnmap_content_for_deep_scan_ports, source_desc_p4_ports = None, "None"
    if phase3_completed_successfully and phase3_content:
        gnmap_content_for_deep_scan_ports = phase3_content; source_desc_p4_ports = "Nmap Phase 3"
        log.info(f"Using Nmap Phase 3 results for {target_subnet_or_ip} to determine ports for its live IPs.")
    elif phase1_content: 
        gnmap_content_for_deep_scan_ports = phase1_content; source_desc_p4_ports = "Nmap Phase 1"
        log.warning(f"Nmap Phase 3 skipped or failed for {target_subnet_or_ip}. Using Nmap Phase 1 results for port details.")
    else: 
        print_red(f"[!] No usable .gnmap content (Nmap P1 or P3) for {target_subnet_or_ip}. Cannot determine ports for Deep Scan or global summary for this target.")
        log.error(f"No Nmap P1 or P3 gnmap content for {target_subnet_or_ip} for Nmap Phase 4 prep. This is unexpected if Nmap P1 succeeded.")
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
            else: log.debug(f"IP {ip_addr} (from {target_subnet_or_ip}, targeted for Nmap P3) has no open ports listed in {source_desc_p4_ports}. Skipping for Nmap P4.")
        results_for_aggregation["phase4_target_ips"].extend(ips_for_deep_scan_within_target) 
        print_green(f"    Found {len(ips_for_deep_scan_within_target)} IPs from {target_subnet_or_ip} with open ports in {source_desc_p4_ports} results for Nmap Phase 4."); log.info(f"Identified {len(ips_for_deep_scan_within_target)} IPs from {target_subnet_or_ip} for Nmap P4 based on {source_desc_p4_ports} data: {ips_for_deep_scan_within_target}")

    # --- Phase 4: Deep Scan ---
    if not ips_for_deep_scan_within_target:
        print_red(f"[!] Skipping Nmap Phase 4 for {target_subnet_or_ip}: No target IPs with open ports identified from {source_desc_p4_ports} results.")
        log.warning(f"No IPs from {target_subnet_or_ip} for Nmap Phase 4 deep scan based on {source_desc_p4_ports} data.")
    elif gnmap_content_for_deep_scan_ports is None: 
        print_red(f"[!] Skipping Nmap Phase 4 for {target_subnet_or_ip}: Missing GNMAP content to determine ports."); log.error(f"Missing gnmap for Nmap P4 of {target_subnet_or_ip} (should be caught earlier).")
    else:
        print_blue(f"\n[+] Nmap Phase 4 for {target_subnet_or_ip}: Starting Deep Scan on {len(ips_for_deep_scan_within_target)} IPs (using {cli_args.parallel_scans} parallel threads)")
        log.info(f"Starting Nmap Phase 4 for {len(ips_for_deep_scan_within_target)} IPs from {target_subnet_or_ip}. Parallelism: {cli_args.parallel_scans}")
        
        scan_func = partial(run_deep_scan, 
                            output_dir_path=main_output_dir_path, 
                            sanitized_scan_title_as_prefix=sanitized_scan_title, 
                            gnmap_content_for_ports=gnmap_content_for_deep_scan_ports)
        
        p4_summary_this_target = {'success': 0, 'skipped_exists': 0, 'skipped_no_ports': 0, 'warning_down': 0, 'failed': 0}
        completed_count, total_tasks, phase4_start_time, progress_bar_length = 0, len(ips_for_deep_scan_within_target), time.time(), 40
        
        sys.stdout.write(f"    Nmap P4 Progress ({target_subnet_or_ip}): [{ ' ' * progress_bar_length }] 0% (0/{total_tasks})"); sys.stdout.flush()

        with ThreadPoolExecutor(max_workers=cli_args.parallel_scans) as executor:
            futures = {executor.submit(scan_func, ip): ip for ip in ips_for_deep_scan_within_target}
            for future in as_completed(futures):
                ip_addr = futures[future]
                completed_count += 1
                percentage = (completed_count / total_tasks) * 100
                filled_length = int(progress_bar_length * completed_count // total_tasks); bar = '#' * filled_length + ' ' * (progress_bar_length - filled_length)
                elapsed_time = time.time() - phase4_start_time; eta_str = ""
                if 0 < completed_count < total_tasks: est_total_time = (elapsed_time / completed_count) * total_tasks; eta = est_total_time - elapsed_time; eta_str = f" ETA: {int(eta//60)}m{int(eta%60)}s" if eta > 0 else ""
                
                current_progress_str = f"Nmap P4 Progress ({target_subnet_or_ip}): [{bar}] {percentage:.1f}% ({completed_count}/{total_tasks}){eta_str}"
                sys.stdout.write(f"\r    {current_progress_str} "); sys.stdout.flush() 
                
                try:
                    target_ip_processed, status_code, message = future.result() 
                    if status_code in p4_summary_this_target: p4_summary_this_target[status_code] += 1
                    else: p4_summary_this_target['failed'] += 1; log.warning(f"Unknown Nmap P4 status: {status_code} for {ip_addr}")

                    sys.stdout.write(f"\r{' ' * (len(current_progress_str) + 6)}\r") 
                    if status_code == "skipped_exists": print(f"    {Fore.MAGENTA}Nmap P4 Skipped (Exists): {ip_addr} (from {target_subnet_or_ip}){Style.RESET_ALL}")
                    elif status_code == "skipped_no_ports": print(f"    {Fore.YELLOW}Nmap P4 Skipped (No Ports): {ip_addr} (from {target_subnet_or_ip}){Style.RESET_ALL}")
                    elif status_code == "warning_down": print(f"    {Fore.YELLOW}Nmap P4 Warning (Down?): {ip_addr} (from {target_subnet_or_ip}){Style.RESET_ALL}")
                    elif status_code == "failed": print(f"    {Fore.RED}Nmap P4 FAILED: {message} ({ip_addr} from {target_subnet_or_ip}){Style.RESET_ALL}")
                    elif status_code == "success": log.info(f"Nmap P4 Success: {message} ({ip_addr} from {target_subnet_or_ip})") 
                    
                    if completed_count < total_tasks: 
                         sys.stdout.write(f"    {current_progress_str} ")
                         sys.stdout.flush()

                except Exception as exc:
                    sys.stdout.write(f"\r{' ' * (len(current_progress_str) + 6)}\r") 
                    print_red(f'\n    [!] IP {ip_addr} (from {target_subnet_or_ip}) generated Nmap P4 future exception: {exc}')
                    log.exception(f"Nmap P4 future exception for {ip_addr} from {target_subnet_or_ip}")
                    p4_summary_this_target['failed'] += 1
                    if completed_count < total_tasks: 
                        sys.stdout.write(f"    {current_progress_str} ")
                        sys.stdout.flush()
            print() 
        
        results_for_aggregation["phase4_summary"] = p4_summary_this_target
        log.info(f"Nmap Phase 4 for {target_subnet_or_ip} complete. Summary: {p4_summary_this_target}")
        print_blue(f"    Nmap Phase 4 Summary for {target_subnet_or_ip}:")
        for k, v_sum in p4_summary_this_target.items(): print(f"        {k.replace('_',' ').capitalize()}: {v_sum}")

    log.info(f"Finished Nmap phases for target {target_subnet_or_ip}."); return results_for_aggregation


def check_masscan_activity_on_block(block_cidr_str, ports, rate, extra_options_str, output_dir_path, scan_title_for_tempfile):
    """
    Runs masscan on a specific block and checks a temporary output file for any content,
    indicating that at least one host was found.
    Returns a tuple: (activity_found_bool, block_cidr_str_passed_in)
    """
    global log
    sanitized_block_name = block_cidr_str.replace('/', '_').replace('.', '-') # Ensure filesystem safe
    temp_masscan_output_file = output_dir_path / f"{scan_title_for_tempfile}_masscan_temp_{sanitized_block_name}.txt"
    
    current_masscan_cmd = ["masscan", block_cidr_str, "-p", ports, "--rate", str(rate)]
    current_masscan_cmd.extend(["--wait", "0"]) 
    current_masscan_cmd.extend(["-oL", str(temp_masscan_output_file)])

    if extra_options_str:
        # Basic check to avoid duplicate -oL if user adds it. More robust parsing would be better.
        if '-oL' in extra_options_str or '--output-filename' in extra_options_str :
            log.warning(f"User's masscan options '{extra_options_str}' for block {block_cidr_str} might conflict with internal -oL. User options appended.")
        current_masscan_cmd.extend(shlex.split(extra_options_str))

    log.debug(f"Checking masscan activity for block {block_cidr_str} with command: {' '.join(current_masscan_cmd)}")
    
    # We don't check return code for masscan "success" in finding hosts, only if the command ran.
    # The presence of content in the temp_masscan_output_file indicates hosts were found.
    command_attempted, _, stdout, stderr = run_external_command(
        current_masscan_cmd, 
        cwd=str(output_dir_path), 
        check_return_code=False, # We rely on file output, not exit code for "found hosts"
        description=f"Masscan activity check on {block_cidr_str}"
    )

    activity_found = False
    if command_attempted: # True if masscan was found and Popen succeeded
        if temp_masscan_output_file.exists() and temp_masscan_output_file.stat().st_size > 0:
            activity_found = True
            # log.info(f"Masscan found activity in block {block_cidr_str}.") # Logged by caller if needed
        else:
            log.debug(f"Masscan found no activity in block {block_cidr_str} (or output file empty/missing). Stdout: '{stdout}', Stderr: '{stderr}'")
    else:
        log.error(f"Masscan command execution failed for block {block_cidr_str}. Stdout: '{stdout}', Stderr: '{stderr}'")

    if temp_masscan_output_file.exists():
        try: temp_masscan_output_file.unlink()
        except OSError as e_del: log.warning(f"Could not delete masscan temp file {temp_masscan_output_file}: {e_del}")
            
    return activity_found, block_cidr_str


def run_hierarchical_masscan_discovery(
    base_cidr_str, 
    initial_prefix_len, # e.g. 16 for /16 blocks
    final_target_prefix_len,   # e.g. 24 for /24 blocks (final target granularity for Nmap)
    masscan_ports, 
    masscan_rate, 
    masscan_extra_options, 
    main_output_dir,
    scan_title, # For temp filenames
    parallel_masscan_workers 
    ):
    global log
    
    try:
        base_network = ipaddress.ip_network(base_cidr_str, strict=False)
    except ValueError as e:
        print_red(f"Invalid Masscan base target CIDR: {base_cidr_str} - {e}")
        log.error(f"Invalid Masscan base target CIDR '{base_cidr_str}': {e}")
        return []

    # Validate prefix hierarchy
    if not (base_network.prefixlen <= initial_prefix_len <= final_target_prefix_len):
        if base_network.prefixlen > initial_prefix_len :
            print_yellow(f"Warning: Base CIDR prefix ({base_network.prefixlen}) is more specific than initial block prefix ({initial_prefix_len}). Adjusting initial to base prefix.")
            initial_prefix_len = base_network.prefixlen
        if initial_prefix_len > final_target_prefix_len:
            print_red(f"Error: Initial block prefix ({initial_prefix_len}) cannot be more specific than final target prefix ({final_target_prefix_len}).")
            log.error(f"Invalid prefix hierarchy: initial={initial_prefix_len}, final={final_target_prefix_len}")
            return []


    print_blue(f"\n--- Starting Hierarchical Masscan Discovery for {base_cidr_str} ---")
    log.info(f"Starting Hierarchical Masscan: Base={base_cidr_str}, Initial Prefix={initial_prefix_len}, Final Target Prefix={final_target_prefix_len}, Ports={masscan_ports}, Rate={masscan_rate}")

    active_intermediate_blocks = []

    # Stage 1: Scan initial larger blocks (if base_cidr is larger than initial_block_prefix_len)
    if base_network.prefixlen < initial_prefix_len:
        initial_blocks_to_scan_stage1 = list(base_network.subnets(new_prefix=initial_prefix_len))
        total_initial_blocks_stage1 = len(initial_blocks_to_scan_stage1)
        
        print_blue(f"    Masscan Stage 1: Scanning {total_initial_blocks_stage1} initial blocks of size /{initial_prefix_len}...")
        log.info(f"Masscan Stage 1: {total_initial_blocks_stage1} blocks of /{initial_prefix_len}")

        with ThreadPoolExecutor(max_workers=parallel_masscan_workers, thread_name_prefix="MasscanInitialBlock") as executor:
            futures_initial = {
                executor.submit(check_masscan_activity_on_block, str(block), masscan_ports, masscan_rate, masscan_extra_options, main_output_dir, scan_title): block 
                for block in initial_blocks_to_scan_stage1
            }
            for i, future in enumerate(as_completed(futures_initial)):
                block_obj_stage1 = futures_initial[future]
                try:
                    activity_found_stage1, block_cidr_returned_stage1 = future.result()
                    if activity_found_stage1:
                        active_intermediate_blocks.append(ipaddress.ip_network(block_cidr_returned_stage1, strict=False)) 
                except Exception as exc:
                    log.error(f"Error processing initial masscan block {block_obj_stage1}: {exc}")
                
                sys.stdout.write(f"\r    Masscan Stage 1: Processed {i+1}/{total_initial_blocks_stage1} initial blocks. Found {len(active_intermediate_blocks)} active. ")
                sys.stdout.flush()
        sys.stdout.write("\n")
        log.info(f"Masscan Stage 1 complete. Found {len(active_intermediate_blocks)} active initial blocks (/{initial_prefix_len}).")
        if not active_intermediate_blocks:
            print_yellow("    Masscan Stage 1: No activity found in any initial blocks. No targets for Nmap.")
            return []
    else: # Base network is already at or smaller than the initial_prefix_len, so it becomes the first "active intermediate block"
        log.info(f"Masscan Stage 1 skipped: Base CIDR {base_cidr_str} is already at or more specific than initial prefix /{initial_prefix_len}.")
        active_intermediate_blocks.append(base_network)


    # Stage 2: Scan final smaller blocks (e.g., /24s) within active intermediate blocks
    final_active_subnets_set = set()
    all_final_blocks_to_scan_stage2 = []
    for active_block_intermediate in active_intermediate_blocks:
        if active_block_intermediate.prefixlen < final_target_prefix_len:
            all_final_blocks_to_scan_stage2.extend(list(active_block_intermediate.subnets(new_prefix=final_target_prefix_len)))
        elif active_block_intermediate.prefixlen == final_target_prefix_len:
            all_final_blocks_to_scan_stage2.append(active_block_intermediate) # Already at target granularity
        else: # Should not happen if initial_prefix_len <= final_target_prefix_len
            log.warning(f"Intermediate block {active_block_intermediate} is smaller than final target prefix {final_target_prefix_len}, adding it directly.")
            all_final_blocks_to_scan_stage2.append(active_block_intermediate)

    
    total_final_blocks_stage2 = len(all_final_blocks_to_scan_stage2)
    if not total_final_blocks_stage2:
        print_yellow(f"    Masscan Stage 2: No final /{final_target_prefix_len} blocks to scan (derived from active intermediate blocks).")
        log.info(f"Masscan Stage 2: No final /{final_target_prefix_len} blocks to scan.")
        return []

    print_blue(f"    Masscan Stage 2: Scanning {total_final_blocks_stage2} final blocks of size /{final_target_prefix_len} within {len(active_intermediate_blocks)} active intermediate block(s)...")
    log.info(f"Masscan Stage 2: {total_final_blocks_stage2} blocks of /{final_target_prefix_len}")

    with ThreadPoolExecutor(max_workers=parallel_masscan_workers, thread_name_prefix="MasscanFinalBlock") as executor:
        futures_final = {
            executor.submit(check_masscan_activity_on_block, str(block), masscan_ports, masscan_rate, masscan_extra_options, main_output_dir, scan_title): block
            for block in all_final_blocks_to_scan_stage2
        }
        for i, future in enumerate(as_completed(futures_final)):
            block_obj_stage2 = futures_final[future]
            try:
                activity_found_stage2, block_cidr_returned_stage2 = future.result()
                if activity_found_stage2:
                    final_active_subnets_set.add(block_cidr_returned_stage2) 
            except Exception as exc:
                log.error(f"Error processing final masscan block {block_obj_stage2}: {exc}")

            sys.stdout.write(f"\r    Masscan Stage 2: Processed {i+1}/{total_final_blocks_stage2} final blocks. Found {len(final_active_subnets_set)} active. ")
            sys.stdout.flush()
    sys.stdout.write("\n")
    
    if final_active_subnets_set:
        print_green(f"--- Hierarchical Masscan Discovery Complete. Found {len(final_active_subnets_set)} active /{final_target_prefix_len} subnets. ---")
        log.info(f"Hierarchical Masscan finished. Found {len(final_active_subnets_set)} active /{final_target_prefix_len} subnets: {sorted(list(final_active_subnets_set))}")
    else:
        print_yellow(f"--- Hierarchical Masscan Discovery Complete. No active /{final_target_prefix_len} subnets found within the active intermediate blocks. ---")
        log.warning(f"Hierarchical Masscan found no active /{final_target_prefix_len} subnets.")
        
    return sorted(list(final_active_subnets_set))


# --- Main Execution ---
def main():
    global log 

    parser = argparse.ArgumentParser(
        description="Perform a multi-phase network scan, processing each target from a list sequentially through all phases. All outputs to a single folder.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("-L", "--host-list", help="Path to the file containing target subnets/IPs (one per line).")
    input_group.add_argument("--masscan-target", help="Large supernet CIDR (e.g., 10.0.0.0/8) to discover active /24s with Masscan.")

    parser.add_argument("--masscan-initial-prefix-len", type=int, default=16, help="Prefix length for Masscan's first broad scan stage (e.g., 16 for /16s). Only used with --masscan-target.")
    # final_target_prefix_len for masscan discovery is implicitly 24, as Nmap phases process /24s.
    parser.add_argument("--masscan-ports", default="80,443,22,21,25,110,143,445,3389,8080", help="Ports for Masscan to check (comma-separated).")
    parser.add_argument("--masscan-rate", type=int, default=1000, help="Transmit rate for Masscan (packets/sec).")
    parser.add_argument("--masscan-options", default="", help="Additional command-line options for Masscan (e.g., '--banners --wait 2').")
    parser.add_argument("--parallel-masscan-workers", type=int, default=5, help="Number of parallel Masscan worker threads for block scanning.")
    
    parser.add_argument("-s", "--scan-title", help="A unique name for this scan (used for main directory name and as a prefix in some global filenames).")
    parser.add_argument("-t", "--top-ports", type=int, default=1000, help="Number of top ports for Nmap Phase 1.")
    parser.add_argument("-i", "--ignore-port", type=int, default=None, metavar='PORT', help="Exclude hosts from Nmap Phase 3/4 if only this port is open in Nmap Phase 1.")
    parser.add_argument("--skip-ping-sweep", action="store_true", help="Skip Nmap Phase 2 ping sweep.")
    parser.add_argument("--phase3", default="-p-", help="Nmap Phase 3 port spec ('-p-', '--top-ports X', 'skip', etc.).")
    parser.add_argument("-j", "--parallel-scans", type=int, default=10, help="Number of parallel Nmap deep scans (Phase 4) *per target subnet*.") 
    
    parser.add_argument("-o", "--output-dir", default=".", help="Parent directory for scan results (the --scan-title folder will be created here).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")
    parser.add_argument("-f", "--force-overwrite", action="store_true", help="Force re-running Nmap scans even if output files exist (applies per phase file).")
    args = parser.parse_args()

    try:
        if os.name == 'posix' and os.geteuid() != 0:
            print_yellow("Warning: This script may require root privileges (or sudo) for certain Nmap/Masscan scan types. Continuing without root...")
    except AttributeError: 
        print_yellow("Warning: Could not check for root privileges on this OS. Some scans might fail if not run as administrator/root.")

    print_blue("--- Scan Configuration ---")
    if args.scan_title is None: args.scan_title = prompt_user("Enter a unique scan title:", validation_func=is_not_empty)
    else: print(f"Scan Title: {args.scan_title}")

    if not args.host_list and not args.masscan_target:
        use_masscan = prompt_user("Use Masscan for initial discovery? (y/N)", default="N", validation_func=is_yes_no).lower().startswith('y')
        if use_masscan:
            args.masscan_target = prompt_user("Enter Masscan target CIDR (e.g., 10.0.0.0/8):", validation_func=is_valid_cidr)
        else:
            args.host_list = prompt_user("Enter path to host list file:", validation_func=is_valid_path)
    
    if args.masscan_target:
        print(f"Masscan Target: {args.masscan_target}")
        print(f"Masscan Initial Block Prefix Length: /{args.masscan_initial_prefix_len}")
        print(f"Masscan Final Target Block Prefix Length: /24 (fixed for Nmap stages)")
        print(f"Masscan Ports: {args.masscan_ports}")
        print(f"Masscan Rate: {args.masscan_rate}")
        print(f"Masscan Parallel Workers: {args.parallel_masscan_workers}")
        if args.masscan_options: print(f"Masscan Extra Options: {args.masscan_options}")
    elif args.host_list:
         print(f"Host List File: {args.host_list}")


    args.top_ports = prompt_user(f"Nmap Top ports for Phase 1:", default=args.top_ports, validation_func=is_positive_int)
    ignore_port_input = input(f"Nmap Port to ignore if solo in Phase 1 (blank for none) [{args.ignore_port or 'None'}]: ").strip()
    if ignore_port_input:
        try: args.ignore_port = int(ignore_port_input)
        except ValueError: print_red("Invalid ignore port. No port will be ignored."); args.ignore_port = None
    
    skip_ping_default = 'Y' if args.skip_ping_sweep else 'N' 
    args.skip_ping_sweep = prompt_user("Skip Nmap Ping Sweep (Phase 2)? (y/N)", default=skip_ping_default, validation_func=is_yes_no).lower().startswith('y')
    
    args.phase3 = prompt_user(f"Nmap Phase 3 port specification ('skip' or nmap options):", default=args.phase3, validation_func=is_valid_phase3)
    args.parallel_scans = prompt_user(f"Parallel Nmap deep scans (Phase 4) per subnet:", default=args.parallel_scans, validation_func=is_positive_int)
    print(f"Base output directory for results: {Path(args.output_dir).resolve()}")
    print(f"Force overwrite existing Nmap files: {'Yes' if args.force_overwrite else 'No'}")

    main_scan_output_dir = Path(args.output_dir).resolve() / args.scan_title
    try:
        main_scan_output_dir.mkdir(parents=True, exist_ok=True)
        print(f"{Fore.BLUE}Main output directory for all files: {main_scan_output_dir}{Style.RESET_ALL}")
    except OSError as e:
        print_red(f"Error creating main output directory {main_scan_output_dir}: {e}"); sys.exit(1)

    log_file_path = main_scan_output_dir / f"{args.scan_title}_main_scan.log" 
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_format = '%(asctime)s - %(levelname)s - [%(name)s] - %(module)s.%(funcName)s:%(lineno)d - %(message)s'
    logging.basicConfig(level=log_level, format=log_format, filename=log_file_path, filemode='a', force=True)
    log = logging.getLogger("NetScannerPro") 
    log.info(f"--- Logging started. Level: {logging.getLevelName(log_level)}. Output File: {log_file_path.name} ---")
    log.info(f"Scan Title: {args.scan_title}")
    log.info(f"Effective CLI Arguments: {args}")

    print_yellow(f"\n--- Starting Scan Campaign: {args.scan_title} ---")
    print_yellow(f"--- All Output To: {main_scan_output_dir.resolve()} ---")
    time.sleep(1) 

    targets_to_process_for_nmap = []
    if args.masscan_target:
        log.info(f"Using Hierarchical Masscan for discovery on target: {args.masscan_target}")
        targets_to_process_for_nmap = run_hierarchical_masscan_discovery(
            args.masscan_target,
            args.masscan_initial_prefix_len,
            24, # Final target prefix for Nmap is /24
            args.masscan_ports, 
            args.masscan_rate, 
            args.masscan_options,
            main_scan_output_dir,
            re.sub(r'[^\w\-.]', '_', args.scan_title), # Sanitized scan_title for temp files
            args.parallel_masscan_workers
        )
        if not targets_to_process_for_nmap:
            print_red("Hierarchical Masscan discovery yielded no active /24 subnets. Exiting Nmap phases.")
            log.error("Hierarchical Masscan found no active /24s. No targets for Nmap phases.")
            # Allow script to proceed to print empty summaries if needed, rather than sys.exit(0)
    elif args.host_list:
        host_file_path = Path(args.host_list)
        log.info(f"Reading targets from host list file: {host_file_path.resolve()}")
        try:
            with open(host_file_path, "r") as f:
                targets_to_process_for_nmap = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            if not targets_to_process_for_nmap:
                print_red(f"No targets found in {host_file_path.resolve()}. Exiting Nmap phases.")
                log.error(f"No targets found in host list file: {host_file_path.resolve()}.")
            else:
                log.info(f"Read {len(targets_to_process_for_nmap)} targets from {host_file_path.resolve()}: {targets_to_process_for_nmap}")
        except IOError as e:
            print_red(f"Error reading host file {host_file_path.resolve()}: {e}")
            log.critical(f"Cannot read host file {host_file_path.resolve()}: {e}"); sys.exit(1)
    else:
        print_red("No target input specified (neither --host-list nor --masscan-target). Exiting.")
        log.critical("No input source for targets specified.")
        sys.exit(1)

    overall_phase3_target_hosts_agg = []
    overall_open_ports_agg = set()
    overall_phase4_target_hosts_agg = [] 
    phase4_results_summary_global_agg = {'success': 0, 'skipped_exists': 0, 'skipped_no_ports': 0, 'warning_down': 0, 'failed': 0}
    
    total_targets_for_nmap_phases = len(targets_to_process_for_nmap)
    nmap_targets_successfully_processed = 0
    
    if total_targets_for_nmap_phases > 0:
        print_blue(f"\n--- Starting Nmap Phased Scan on {total_targets_for_nmap_phases} Targets ---")
    else: 
        print_yellow("No targets to process with Nmap phases based on discovery/input list.")
        log.info("No targets available for Nmap processing.")
        
    for i, current_target_for_nmap_phase in enumerate(targets_to_process_for_nmap):
        print_purple(f"\n--- Processing Nmap Target {i+1}/{total_targets_for_nmap_phases}: {current_target_for_nmap_phase} ---")
        log.info(f"--- Starting Nmap phases for target {i+1}/{total_targets_for_nmap_phases}: {current_target_for_nmap_phase} ---")

        target_processing_results = process_single_target(
            current_target_for_nmap_phase,
            args,
            main_scan_output_dir, 
            log 
        )

        if target_processing_results:
            nmap_targets_successfully_processed +=1 
            overall_phase3_target_hosts_agg.extend(target_processing_results.get("phase3_target_ips", []))
            overall_open_ports_agg.update(target_processing_results.get("open_ports_found", set()))
            overall_phase4_target_hosts_agg.extend(target_processing_results.get("phase4_target_ips", []))
            
            p4_summary_for_target = target_processing_results.get("phase4_summary", {})
            for key in phase4_results_summary_global_agg: 
                phase4_results_summary_global_agg[key] += p4_summary_for_target.get(key, 0)
            
            log.info(f"--- Finished Nmap phases and aggregated results for target: {current_target_for_nmap_phase} ---")
            print_green(f"--- Successfully completed Nmap phases for target: {current_target_for_nmap_phase} ---")
        else:
            log.warning(f"--- Nmap processing FAILED or returned no results for target: {current_target_for_nmap_phase}. Check logs for details. ---")
            print_red(f"--- Nmap processing FAILED for target: {current_target_for_nmap_phase}. Check log: {log_file_path.name} ---")
        
        progress_percentage = ((i + 1) / total_targets_for_nmap_phases) * 100 if total_targets_for_nmap_phases > 0 else 0
        print_blue(f"=== Overall Nmap Target Progress: {i+1}/{total_targets_for_nmap_phases} targets initiated ({progress_percentage:.1f}%). {nmap_targets_successfully_processed} successfully completed Nmap processing. ===")


    print_blue("\n--- Generating Global Summary Files ---")
    log.info("Generating global summary files.")

    if overall_phase3_target_hosts_agg:
        unique_overall_p3_hosts = sorted(list(set(overall_phase3_target_hosts_agg)))
        g_p3_file = main_scan_output_dir / f"{args.scan_title}_ALL_NmapPhase3_target_hosts.txt" 
        try:
            with open(g_p3_file, "w") as f: f.write("\n".join(unique_overall_p3_hosts) + "\n")
            print_green(f"[+] {len(unique_overall_p3_hosts)} unique hosts targeted for Nmap P3 (globally) saved to {g_p3_file.name}")
            log.info(f"Saved {len(unique_overall_p3_hosts)} global Nmap P3 target hosts to {g_p3_file.name}")
        except IOError as e: print_red(f"Error writing global Nmap P3 hosts file {g_p3_file.name}: {e}"); log.error(f"Err writing global Nmap P3 file: {e}")
    else: print_yellow("[!] No hosts were targeted for Nmap Phase 3 globally."); log.info("No global Nmap P3 target hosts.")

    if overall_open_ports_agg:
        sorted_ports_globally = sorted([int(p) for p in overall_open_ports_agg])
        g_ports_file = main_scan_output_dir / f"{args.scan_title}_ALL_Nmap_open_ports.txt" 
        try:
            g_ports_file.write_text(",".join(map(str, sorted_ports_globally)) + "\n")
            print_green(f"[+] All {len(sorted_ports_globally)} unique open ports (globally from Nmap scans) saved to {g_ports_file.name}")
            log.info(f"Saved {len(sorted_ports_globally)} global Nmap open ports to {g_ports_file.name}")
        except IOError as e: print_red(f"Error writing global Nmap ports file {g_ports_file.name}: {e}"); log.error(f"Err writing global Nmap ports file: {e}")
    else: print_yellow("[!] No open ports found globally across all Nmap targets."); log.info("No global Nmap open ports found.")

    if overall_phase4_target_hosts_agg: 
        unique_overall_p4_hosts = sorted(list(set(overall_phase4_target_hosts_agg)))
        g_p4_file = main_scan_output_dir / f"{args.scan_title}_ALL_NmapPhase4_target_hosts.txt" 
        try:
            with open(g_p4_file, "w") as f: f.write("\n".join(unique_overall_p4_hosts) + "\n")
            print_green(f"[+] {len(unique_overall_p4_hosts)} unique hosts targeted for Nmap P4 Deep Scan (globally) saved to {g_p4_file.name}")
            log.info(f"Saved {len(unique_overall_p4_hosts)} global Nmap P4 target hosts to {g_p4_file.name}")
        except IOError as e: print_red(f"Error writing global Nmap P4 hosts file {g_p4_file.name}: {e}"); log.error(f"Err writing global Nmap P4 file: {e}")
    else: print_yellow("[!] No hosts were targeted for Nmap Phase 4 Deep Scan globally."); log.info("No global Nmap P4 target hosts.")

    print_blue("\n[+] Global Nmap Phase 4 Deep Scan Summary (across all targets):")
    if sum(phase4_results_summary_global_agg.values()) > 0:
        for k_sum, v_sum in phase4_results_summary_global_agg.items(): print_green(f"    {k_sum.replace('_',' ').capitalize()}: {v_sum}")
        log.info(f"Global Nmap Phase 4 Summary: {phase4_results_summary_global_agg}")
    else: print_yellow("    No Nmap Phase 4 deep scans were initiated globally (or all failed before summary)."); log.info("No Nmap P4 scans initiated/summarized globally.")

    print_blue(f"\n--- Scan Campaign {args.scan_title} Complete ---")
    print_blue(f"--- All results are in: {main_scan_output_dir.resolve()} ---")
    print_blue(f"--- Main log file: {log_file_path.resolve()} ---")
    log.info(f"--- Scan Campaign {args.scan_title} Complete ---")
    
    logging.shutdown()

if __name__ == "__main__":
    main()
