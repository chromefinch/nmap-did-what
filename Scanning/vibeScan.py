#!/usr/bin/env python3
# Robust Network Scanner with Phases 1-5
# Phase 4: Service Detection
# Phase 5: Safe Targeted NSE Scripts
# Updated for STABILITY: Stream processing, Bounded execution, Resume Checkpoints, and Work Hours Window.

import argparse
import os
import subprocess
import sys
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from functools import partial
import logging
import shlex
import time
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
import gc 

try:
    from colorama import init, Fore, Style
    init(autoreset=True) # Auto-reset color after each print
except ImportError:
    print("Warning: colorama library not found. Colors will not be displayed.")
    print("Install it using: pip install colorama")
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
                if validation_func(value): break
                else: print_red(error_msg)
            else: break
        elif default is None:
            print_red("This field cannot be empty.")
    
    if isinstance(default, int):
        try: return int(value)
        except ValueError: return default
    return value

# --- Validation Functions ---
def is_valid_path(path_str): return Path(path_str).is_file() and os.access(Path(path_str), os.R_OK)
def is_not_empty(value): return bool(value)
def is_positive_int(value):
    try: return int(value) > 0
    except ValueError: return False
def is_valid_phase3(value): return bool(value)
def is_yes_no(value): return value.lower() in ['y', 'n', 'yes', 'no']
def is_valid_time_format(value):
    try:
        datetime.strptime(value, "%H:%M")
        return True
    except ValueError:
        return False

# --- Work Hours Logic ---
def enforce_work_window(start_str, end_str):
    """
    Checks if current time is within start_str (HH:MM) and end_str (HH:MM).
    If not, sleeps until the start time.
    """
    if not start_str or not end_str:
        return

    while True:
        now = datetime.now()
        current_time = now.time()
        
        try:
            start_time = datetime.strptime(start_str, "%H:%M").time()
            end_time = datetime.strptime(end_str, "%H:%M").time()
        except ValueError:
            log.error(f"Invalid time format in enforce_window: {start_str}-{end_str}")
            return

        is_working_hours = False
        
        if start_time < end_time: # e.g., 09:00 to 17:00
            if start_time <= current_time <= end_time:
                is_working_hours = True
        else: # Overnight, e.g., 22:00 to 06:00
            if current_time >= start_time or current_time <= end_time:
                is_working_hours = True
        
        if is_working_hours:
            return # Continue execution

        # Calculate sleep time
        now_dt = datetime.now()
        start_dt = now_dt.replace(hour=start_time.hour, minute=start_time.minute, second=0, microsecond=0)
        
        # If the target start time for "today" has passed, scheduled for tomorrow
        if now_dt > start_dt:
             start_dt += timedelta(days=1)
        
        wait_seconds = (start_dt - now_dt).total_seconds()
        
        print_yellow(f"\n[!] Outside scan window ({start_str}-{end_str}). Current time: {current_time.strftime('%H:%M')}.")
        print_yellow(f"    Pausing scan for {int(wait_seconds/3600)}h {int((wait_seconds%3600)/60)}m until {start_dt.strftime('%Y-%m-%d %H:%M:%S')}...")
        log.info(f"Outside work hours. Sleeping {wait_seconds}s until {start_dt}.")
        
        time.sleep(wait_seconds)
        
        print_green("\n[+] Work hours resumed. Waking up and continuing scan...")
        log.info("Resuming scan after sleep window.")

# --- Resume Logic: Check for Valid XML ---
def is_xml_completed(xml_path):
    """
    Checks if an Nmap XML file seems to have completed successfully 
    by looking for the closing </nmaprun> tag.
    Prevents resuming from corrupted/partial scan files caused by crashes.
    """
    path = Path(xml_path)
    # Check if file exists and has some content
    if not path.exists() or path.stat().st_size < 50:
        return False
    
    try:
        with open(path, 'rb') as f:
            # Read the last 512 bytes to check for closing tag
            f.seek(0, 2) # Seek to end
            size = f.tell()
            f.seek(max(0, size - 512), 0)
            tail = f.read()
            return b'</nmaprun>' in tail
    except Exception:
        # If we can't read it, assume it's corrupt
        return False

# --- Core Nmap Functions ---
def run_command(cmd_list, cwd=None, check=True, description="Running command"):
    global log
    cmd_str = shlex.join(cmd_list)
    effective_cwd_path = Path(cwd).resolve() if cwd else Path.cwd()
    
    # Log the start of the command
    log.info(f"EXEC: {cmd_str} (in {effective_cwd_path})")

    try:
        process = subprocess.Popen(
            cmd_list, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            cwd=str(effective_cwd_path)
        )
        stdout, stderr = process.communicate()

        # Detailed logging of output
        if stdout: 
            log.debug(f"STDOUT ({cmd_str}):\n{stdout.strip()}")
        if stderr:
            # If command failed, stderr is ERROR, otherwise it's typically info/warning
            if process.returncode != 0:
                log.error(f"STDERR ({cmd_str}):\n{stderr.strip()}")
            else:
                log.info(f"STDERR ({cmd_str} - RC0):\n{stderr.strip()}")

        if check and process.returncode != 0:
            log.error(f"Command failed (Exit: {process.returncode}): {cmd_str}")
            raise subprocess.CalledProcessError(process.returncode, cmd_list, output=stdout, stderr=stderr)

        return stdout, stderr
    except Exception as e:
        log.exception(f"Exception running command: {cmd_str}")
        raise

# --- Streaming GNMAP Parsing (Memory Safe) ---
def stream_gnmap_hosts_with_ports(gnmap_file_path):
    """
    Generator that reads a .gnmap file line by line (memory safe).
    Yields tuple: (ip, [list_of_ports]) for hosts that are UP and have OPEN ports.
    """
    port_pattern = re.compile(r"(\d+)/(?:open|open\|filtered)")
    host_pattern = re.compile(r"Host:\s+([\d.:a-fA-F]+)")
    
    try:
        with open(gnmap_file_path, 'r') as f:
            for line in f:
                if 'Ports:' in line and 'Status: Up' not in line: 
                    match_host = host_pattern.search(line)
                    if match_host:
                        ip = match_host.group(1)
                        ports = [int(p) for p in port_pattern.findall(line)]
                        if ports:
                            yield ip, sorted(ports)
    except Exception as e:
        log.error(f"Error streaming gnmap {gnmap_file_path}: {e}")

def parse_gnmap_extract_all_ips(gnmap_file_path):
    """Parses all IPs marked as Up from a gnmap file (Memory efficient)."""
    live_hosts = set()
    up_host_pattern = re.compile(r"Host:\s+([\d.:a-fA-F]+).*Status:\s+Up")
    try:
        with open(gnmap_file_path, 'r') as f:
            for line in f:
                match = up_host_pattern.search(line)
                if match:
                    live_hosts.add(match.group(1))
    except FileNotFoundError: pass
    return live_hosts

def parse_gnmap_filter_no_open_stream(gnmap_file_path, ignore_port=None):
    """
    Reads Phase 1 gnmap. Returns set of IPs that should proceed.
    Filters out hosts that only have `ignore_port` open.
    """
    valid_hosts = set()
    try:
        # Use the streaming generator
        for ip, ports in stream_gnmap_hosts_with_ports(gnmap_file_path):
            if ignore_port is not None:
                if len(ports) == 1 and ports[0] == int(ignore_port):
                    continue
            valid_hosts.add(ip)
    except Exception as e:
        log.error(f"Error filtering gnmap {gnmap_file_path}: {e}")
    return valid_hosts

def get_all_open_ports_from_file(gnmap_file_path):
    """Scans entire file for unique ports."""
    ports = set()
    port_pattern = re.compile(r"(\d+)/(?:open|open\|filtered)")
    try:
        with open(gnmap_file_path, 'r') as f:
            for line in f:
                ports.update(int(p) for p in port_pattern.findall(line))
    except: pass
    return sorted(list(ports))

# --- XML Parsing for Service Detection (Phase 5 Prep) ---
def parse_xml_services(xml_file_path):
    """
    Parses Nmap XML output to find services detected on open ports.
    Returns a list of dicts: [{'ip': '...', 'port': '...', 'service': '...'}, ...]
    """
    detected_services = []
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        
        for host in root.findall('host'):
            status = host.find('status')
            if status is None or status.get('state') != 'up':
                continue
            
            address = host.find('address')
            if address is None: continue
            ip_addr = address.get('addr')

            ports = host.find('ports')
            if ports is None: continue

            for port in ports.findall('port'):
                state = port.find('state')
                if state is None or state.get('state') != 'open':
                    continue
                
                service = port.find('service')
                port_id = port.get('portid')
                
                service_name = "unknown"
                if service is not None:
                    service_name = service.get('name', 'unknown')
                    # Clean up service name (remove ssl/ prefixes if handled by logic)
                    if service.get('tunnel') == 'ssl':
                        service_name = f"ssl/{service_name}"

                detected_services.append({
                    'ip': ip_addr,
                    'port': port_id,
                    'service': service_name.lower()
                })
    except ET.ParseError:
        log.warning(f"XML Parse Error/Incomplete file: {xml_file_path}")
    except Exception as e:
        log.error(f"General error parsing XML {xml_file_path}: {e}")
    
    return detected_services

# --- Phase 4: Deep Scan Task ---
def run_deep_scan(ip_to_scan, ports_to_scan, output_dir_path, sanitized_scan_title_as_prefix):
    global log
    ip_sanitized_for_filename = ip_to_scan.replace(':', '_').replace('.', '-') 
    file_basename = f"{sanitized_scan_title_as_prefix}_phase4_DeepScan_HOST_{ip_sanitized_for_filename}"
    nmap_output_prefix_abs = output_dir_path / file_basename 
    xml_file_abs = nmap_output_prefix_abs.with_suffix(".xml")

    # RESUME LOGIC: Check if Valid XML Exists
    if is_xml_completed(xml_file_abs): 
        return ip_to_scan, "skipped_exists", f"Output exists ({xml_file_abs.name})", xml_file_abs
    elif xml_file_abs.exists():
        # Exists but incomplete (corrupt) -> Re-scan
        log.warning(f"Found partial/corrupt XML for {ip_to_scan}. Re-scanning.")

    if not ports_to_scan:
        return ip_to_scan, "skipped_no_ports", "No open ports passed to task", None

    port_str = ",".join(map(str, ports_to_scan))
    # Nmap -A includes OS detection, version detection, script scanning, and traceroute
    nmap_cmd_base = ["nmap", "-A", "-T4", "--max-retries", "3", "--max-rtt-timeout", "300ms", "--host-timeout", "15m", "-Pn", "-p", port_str, ip_to_scan, "-oA", str(nmap_output_prefix_abs)]
    nmap_cmd = ["nmap", "-6"] + nmap_cmd_base[1:] if ':' in ip_to_scan else nmap_cmd_base

    try:
        stdout, stderr = run_command(nmap_cmd, cwd=str(output_dir_path), check=True, description=f"Phase 4: Deep Scan {ip_to_scan}")
        if "Note: Host seems down" in stdout:
            return ip_to_scan, "warning_down", "Host seems down during scan", xml_file_abs
        return ip_to_scan, "success", "Scan completed", xml_file_abs
    except Exception as e:
        return ip_to_scan, "failed", str(e), None

# --- Phase 5: Targeted NSE Task ---
def run_targeted_nse(target_info, output_dir_path, sanitized_scan_title_as_prefix, smb_creds):
    """
    Runs specific safe NSE scripts based on the service name found in Phase 4.
    """
    global log
    ip_to_scan = target_info['ip']
    port_to_scan = target_info['port']
    service_name = target_info['service']

    # --- NSE SELECTION LOGIC ---
    script_cmd = []
    script_name_for_file = "generic-service"
    
    # 1. HTTP/HTTPS
    if 'http' in service_name or 'https' in service_name or 'ssl' in service_name:
        base_http_scripts = "http-title,http-headers,http-methods,http-robots.txt,http-server-header"
        if 'https' in service_name or 'ssl' in service_name:
            script_cmd = ["--script", f"{base_http_scripts},ssl-enum-ciphers,ssl-cert,ssl-date"]
            script_name_for_file = "https-enum"
        else:
            script_cmd = ["--script", base_http_scripts]
            script_name_for_file = "http-enum"
    # 2. SSH
    elif 'ssh' in service_name:
        script_cmd = ["--script", "ssh-auth-methods,ssh2-enum-algos,ssh-hostkey"]
        script_name_for_file = "ssh-enum"
    # 3. RDP
    elif 'ms-wbt-server' in service_name or 'rdp' in service_name:
        script_cmd = ["--script", "rdp-enum-encryption,rdp-ntlm-info"]
        script_name_for_file = "rdp-enum"
    # 4. SMB / NetBIOS
    elif 'microsoft-ds' in service_name or 'netbios-ssn' in service_name or 'smb' in service_name:
        script_cmd = ["--script", "smb-enum-shares,smb-ls,smb-os-discovery,smb-security-mode,smb-protocols"]
        script_name_for_file = "smb-enum"
        if smb_creds and smb_creds.get('username'):
            auth_args = f"smbusername={smb_creds['username']},smbpassword={smb_creds['password']}"
            if smb_creds.get('domain'): auth_args += f",smbdomain={smb_creds['domain']}"
            script_cmd.extend(["--script-args", auth_args])
    # 5. FTP
    elif 'ftp' in service_name:
        script_cmd = ["--script", "ftp-anon,ftp-syst"]
        script_name_for_file = "ftp-enum"
    # 6. SMTP
    elif 'smtp' in service_name:
        script_cmd = ["--script", "smtp-commands,smtp-open-relay"]
        script_name_for_file = "smtp-relay"
    # 7. DNS
    elif 'domain' in service_name or 'dns' in service_name:
        script_cmd = ["--script", "dns-recursion,dns-service-discovery"]
        script_name_for_file = "dns-enum"
    # 8. Printers
    elif any(x in service_name for x in ['printer', 'jetdirect', 'hp', 'xerox', 'zebra']):
         script_cmd = ["--script", "printer-info"]
         script_name_for_file = "printer-info"
    elif 'ipp' in service_name or 'cups' in service_name:
         script_cmd = ["--script", "ipp-enum,cups-info"]
         script_name_for_file = "ipp-info"
    # 9. SNMP
    elif 'snmp' in service_name:
        script_cmd = ["--script", "snmp-info,snmp-sysdescr,snmp-processes"]
        script_name_for_file = "snmp-info"
    # 10. High Value / Infra
    elif 'ldap' in service_name:
        script_cmd = ["--script", "ldap-rootdse"]
        script_name_for_file = "ldap-info"
    elif 'memcached' in service_name:
        script_cmd = ["--script", "memcached-info"]
        script_name_for_file = "memcached-info"
    elif 'elasticsearch' in service_name:
        script_cmd = ["--script", "elasticsearch-info"]
        script_name_for_file = "elasticsearch-info"
    elif 'rsync' in service_name:
        script_cmd = ["--script", "rsync-list-modules"]
        script_name_for_file = "rsync-modules"
    elif 'ajp' in service_name:
        script_cmd = ["--script", "ajp-methods,ajp-headers"]
        script_name_for_file = "ajp-info"
    # 11. Databases
    elif 'mysql' in service_name:
        script_cmd = ["--script", "mysql-info,mysql-empty-password"]
        script_name_for_file = "mysql-info"
    elif 'postgresql' in service_name or 'pgsql' in service_name:
        script_cmd = ["--script", "pgsql-info"]
        script_name_for_file = "pgsql-info"
    elif 'ms-sql-s' in service_name or 'ms-sql' in service_name:
        script_cmd = ["--script", "ms-sql-info,ms-sql-ntlm-info"]
        script_name_for_file = "mssql-info"
        if smb_creds and smb_creds.get('username'):
            auth_args = f"mssql.username={smb_creds['username']},mssql.password={smb_creds['password']}"
            if smb_creds.get('domain'): auth_args += f",mssql.domain={smb_creds['domain']}"
            script_cmd.extend(["--script-args", auth_args])
    elif 'mongodb' in service_name:
        script_cmd = ["--script", "mongodb-info,mongodb-databases"]
        script_name_for_file = "mongodb-info"
    elif 'redis' in service_name:
        script_cmd = ["--script", "redis-info"]
        script_name_for_file = "redis-info"
    # 12. NFS/VNC/Telnet
    elif 'nfs' in service_name:
        script_cmd = ["--script", "nfs-showmount,nfs-ls,nfs-statfs"]
        script_name_for_file = "nfs-enum"
    elif 'vnc' in service_name:
        script_cmd = ["--script", "vnc-info,vnc-title"]
        script_name_for_file = "vnc-info"
    elif 'telnet' in service_name:
        script_cmd = ["--script", "telnet-encryption,banner"]
        script_name_for_file = "telnet-info"
    else:
        return ip_to_scan, port_to_scan, "skipped_no_script", f"No script for service '{service_name}'"

    # --- EXECUTE NSE ---
    ip_sanitized = ip_to_scan.replace(':', '_').replace('.', '-')
    file_basename = f"{sanitized_scan_title_as_prefix}_phase5_NSE_{script_name_for_file}_HOST_{ip_sanitized}_Port{port_to_scan}"
    output_prefix = output_dir_path / file_basename
    
    # RESUME LOGIC: Check if Valid XML Exists
    xml_path = output_prefix.with_suffix(".xml")
    if is_xml_completed(xml_path):
        return ip_to_scan, port_to_scan, "skipped_exists", "Output exists"

    # Construct Nmap Command
    nmap_base = ["nmap", "-Pn", "-n", "-p", str(port_to_scan), "--script-timeout", "2m", "--host-timeout", "5m"]
    nmap_base.extend(script_cmd)
    nmap_base.append(ip_to_scan)
    nmap_base.extend(["-oA", str(output_prefix)])
    
    full_cmd = ["nmap", "-6"] + nmap_base[1:] if ':' in ip_to_scan else nmap_base

    try:
        run_command(full_cmd, cwd=str(output_dir_path), check=True, description=f"Phase 5: {script_name_for_file} on {ip_to_scan}:{port_to_scan}")
        return ip_to_scan, port_to_scan, "success", f"Ran {script_name_for_file}"
    except Exception as e:
        return ip_to_scan, port_to_scan, "failed", str(e)


# --- BOUNDED EXECUTOR (Crash Prevention) ---
def execute_bounded_tasks(executor, task_generator, max_queue_size, work_window, progress_prefix="Progress"):
    """
    Submits tasks to executor but keeps the queue size bounded.
    Prevents generating millions of Future objects in memory.
    """
    start_time_str, end_time_str = work_window
    active_futures = set()
    total_submitted = 0
    completed_count = 0
    
    iterator = iter(task_generator)
    done_generating = False

    while True:
        # Check Work Hours periodically
        if start_time_str and end_time_str:
            enforce_work_window(start_time_str, end_time_str)

        # 1. Fill queue up to max_queue_size
        while len(active_futures) < max_queue_size and not done_generating:
            try:
                task_item = next(iterator)
                if len(task_item) == 3: func, args, kwargs = task_item
                elif len(task_item) == 2: func, args = task_item; kwargs = {}
                else: continue
                
                future = executor.submit(func, *args, **kwargs)
                active_futures.add(future)
                total_submitted += 1
            except StopIteration:
                done_generating = True
            except Exception as e:
                log.error(f"Error generating task: {e}")
                done_generating = True

        # 2. Check exit condition
        if not active_futures and done_generating:
            break

        # 3. Wait for at least one task to complete
        done, not_done = wait(active_futures, return_when=FIRST_COMPLETED)
        
        # 4. Process results
        for future in done:
            active_futures.remove(future)
            completed_count += 1
            yield future 
            
        if completed_count % 50 == 0:
            sys.stdout.write(f"\r    {progress_prefix}: Completed {completed_count} tasks... ")
            sys.stdout.flush()

    sys.stdout.write("\r" + " " * 60 + "\r")


def process_single_target(target_subnet_or_ip, cli_args, main_output_dir_path, current_log_instance, smb_creds):
    global log
    log = current_log_instance 
    
    # Check window before starting target
    if cli_args.start_time and cli_args.end_time:
        enforce_work_window(cli_args.start_time, cli_args.end_time)

    sanitized_target_name = re.sub(r'[^\w\-.]', '_', target_subnet_or_ip) 
    sanitized_scan_title = re.sub(r'[^\w\-.]', '_', cli_args.scan_title)
    
    print_blue(f"\n--- Starting Analysis of {target_subnet_or_ip} ---")
    log.info(f"Target Start: {target_subnet_or_ip}")

    # Aggregation stores limited data to save RAM
    results_agg = {
        "phase3_target_ips": [], "open_ports_found": set(), "phase4_target_ips": [],
        "phase4_summary": {'success': 0, 'skipped_exists': 0, 'skipped_no_ports': 0, 'warning_down': 0, 'failed': 0},
        "phase5_summary": {'success': 0, 'skipped_exists': 0, 'skipped_no_script': 0, 'failed': 0}
    }

    # --- Phase 1: Discovery ---
    phase1_basename = f"{sanitized_scan_title}_{sanitized_target_name}_phase1_Top{cli_args.top_ports}Ports"
    phase1_xml = main_output_dir_path / f"{phase1_basename}.xml"
    phase1_gnmap = main_output_dir_path / f"{phase1_basename}.gnmap"

    if not cli_args.force_overwrite and phase1_xml.exists():
        print_purple(f"[*] Phase 1 Skipped: {phase1_xml.name} exists.")
    else:
        # Note: --max-retries 1 for speed on /8
        p1_cmd = ["nmap", "-sS", "-T4", "--max-retries", "1", "--max-rtt-timeout", "300ms", "--host-timeout", "3m", "-n", "-Pn", target_subnet_or_ip, "--top-ports", str(cli_args.top_ports), "-oA", str(main_output_dir_path / phase1_basename)]
        try:
            run_command(p1_cmd, cwd=str(main_output_dir_path), description=f"Phase 1: Discovery {target_subnet_or_ip}")
        except Exception as e: log.error(f"Phase 1 failed: {e}"); return None

    if not phase1_gnmap.exists():
        log.error("Phase 1 output missing"); return None

    # STREAMING PARSE Phase 1
    phase1_filtered_ips = parse_gnmap_filter_no_open_stream(phase1_gnmap, cli_args.ignore_port)
    print_green(f"    Phase 1: {len(phase1_filtered_ips)} hosts active (filtered).")

    # --- Phase 2: Ping Sweep (Optional) ---
    phase2_live_ips = set()
    if not cli_args.skip_ping_sweep:
        # Check window before Phase 2
        if cli_args.start_time and cli_args.end_time: enforce_work_window(cli_args.start_time, cli_args.end_time)

        p2_basename = f"{sanitized_scan_title}_{sanitized_target_name}_phase2_PingSweep"
        p2_xml = main_output_dir_path / f"{p2_basename}.xml"
        p2_gnmap = main_output_dir_path / f"{p2_basename}.gnmap"
        
        if not cli_args.force_overwrite and p2_xml.exists():
            print_purple(f"[*] Phase 2 Skipped: {p2_xml.name} exists.")
        else:
            p2_cmd = ["nmap", "-sn", "-T4", "-n", target_subnet_or_ip, "-oA", str(main_output_dir_path / p2_basename)]
            try:
                run_command(p2_cmd, cwd=str(main_output_dir_path), description=f"Phase 2: Ping Sweep {target_subnet_or_ip}")
            except Exception as e: log.error(f"Phase 2 failed: {e}")
        
        if p2_gnmap.exists():
            phase2_live_ips = parse_gnmap_extract_all_ips(p2_gnmap)
        print_green(f"    Phase 2: {len(phase2_live_ips)} hosts up.")

    # --- Combine Targets for Phase 3 ---
    ips_for_phase3 = sorted(list(phase1_filtered_ips.union(phase2_live_ips)))
    
    # Clean up memory
    del phase1_filtered_ips
    del phase2_live_ips
    gc.collect()

    results_agg["phase3_target_ips"].extend(ips_for_phase3)
    if not ips_for_phase3:
        print_red("[!] No live IPs found. Skipping subsequent phases.")
        return results_agg

    # --- Phase 3: Port Discovery ---
    p3_basename = f"{sanitized_scan_title}_{sanitized_target_name}_phase3_PortDisco"
    p3_gnmap = main_output_dir_path / f"{p3_basename}.gnmap"

    if cli_args.phase3.lower() != 'skip':
        # Check window before Phase 3
        if cli_args.start_time and cli_args.end_time: enforce_work_window(cli_args.start_time, cli_args.end_time)

        p3_xml = main_output_dir_path / f"{p3_basename}.xml"

        if not cli_args.force_overwrite and p3_xml.exists():
            print_purple(f"[*] Phase 3 Skipped: {p3_xml.name} exists.")
        else:
            # Create temp target file
            p3_targets_file = main_output_dir_path / f"{p3_basename}_targets.tmp"
            with open(p3_targets_file, 'w') as f: f.write("\n".join(ips_for_phase3))
            
            p3_args = shlex.split(cli_args.phase3) if cli_args.phase3 != "-p-" else ["-p-"]
            p3_cmd = ["nmap", "-sS", "-Pn", "-n", "-T4", "--min-rate", "800", "-iL", str(p3_targets_file)] + p3_args + ["-oA", str(main_output_dir_path / p3_basename)]
            
            try:
                run_command(p3_cmd, cwd=str(main_output_dir_path), description=f"Phase 3: Port Scan on {len(ips_for_phase3)} IPs")
            except Exception as e: log.error(f"Phase 3 failed: {e}")
            finally: 
                if p3_targets_file.exists(): p3_targets_file.unlink()

    # --- Phase 4: Deep Service Scan (Streaming) ---
    source_gnmap = p3_gnmap if p3_gnmap.exists() else phase1_gnmap
    
    if not source_gnmap.exists():
        print_red("[!] No GNMAP data available for Phase 4.")
        return results_agg

    results_agg["open_ports_found"].update(get_all_open_ports_from_file(source_gnmap))

    print_blue(f"\n[+] Phase 4: Deep Service Scan (Streaming from {source_gnmap.name})...")
    print_blue(f"    Bounded Queue Size: {cli_args.parallel_scans * 2} tasks (Crash Prevention)")
    if cli_args.start_time: print_yellow(f"    Active Work Hours Window: {cli_args.start_time} - {cli_args.end_time}")

    # Generator for Phase 4 tasks
    def phase4_task_generator():
        for ip, ports in stream_gnmap_hosts_with_ports(source_gnmap):
            if ip in ips_for_phase3: # Only scan if it was in our target list (safety check)
                results_agg["phase4_target_ips"].append(ip)
                yield run_deep_scan, (ip, ports, main_output_dir_path, sanitized_scan_title)

    phase4_xml_files = [] # Track outputs for Phase 5

    work_window_tuple = (cli_args.start_time, cli_args.end_time)

    with ThreadPoolExecutor(max_workers=cli_args.parallel_scans) as executor:
        # Using bounded executor to prevent OOM
        for future in execute_bounded_tasks(executor, phase4_task_generator(), 
                                            max_queue_size=cli_args.parallel_scans * 3, 
                                            work_window=work_window_tuple,
                                            progress_prefix="P4 Scan"):
            try:
                res_ip, status, msg, xml_path = future.result()
                results_agg["phase4_summary"][status] = results_agg["phase4_summary"].get(status, 0) + 1
                if xml_path and (status == "success" or status == "skipped_exists"):
                    phase4_xml_files.append(xml_path)
            except Exception as e:
                log.error(f"Phase 4 Future Err: {e}")
                results_agg["phase4_summary"]['failed'] += 1
    
    # --- Phase 5: Targeted NSE Scans (Streaming) ---
    if phase4_xml_files:
        print_blue(f"\n[+] Phase 5: Targeted NSE Scans (Analyzing {len(phase4_xml_files)} XML files)...")
        
        # Generator for Phase 5 tasks (Lazy XML parsing)
        def phase5_task_generator():
            for xml_f in phase4_xml_files:
                # We parse XMLs on demand here, rather than all at once
                services = parse_xml_services(xml_f)
                for svc in services:
                    yield run_targeted_nse, (svc, main_output_dir_path, sanitized_scan_title, smb_creds)

        with ThreadPoolExecutor(max_workers=cli_args.parallel_scans) as executor:
             for future in execute_bounded_tasks(executor, phase5_task_generator(), 
                                                 max_queue_size=cli_args.parallel_scans * 3, 
                                                 work_window=work_window_tuple,
                                                 progress_prefix="P5 NSE"):
                try:
                    ip, port, status, msg = future.result()
                    results_agg["phase5_summary"][status] = results_agg["phase5_summary"].get(status, 0) + 1
                    if status == "success":
                        log.info(f"P5 Success: {ip}:{port} -> {msg}")
                    elif status == "failed":
                        log.debug(f"P5 Fail: {ip}:{port} - {msg}")
                except Exception as e:
                    log.error(f"Phase 5 Future Err: {e}")

        # Summary Print
        print_blue("\n    Phase 5 Summary:")
        for k, v in results_agg["phase5_summary"].items():
            if v > 0: print(f"      {k}: {v}")

    else:
        print_yellow("    Skipping Phase 5: No services identified from Phase 4.")

    gc.collect() # Force cleanup
    return results_agg

# --- Main Execution ---
def main():
    global log 

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-s", "--scan-title", help="Unique name for this scan.")
    parser.add_argument("-L", "--host-list", help="File with target subnets/IPs.")
    parser.add_argument("-t", "--top-ports", type=int, default=1000, help="Top ports for Phase 1.")
    parser.add_argument("-i", "--ignore-port", type=int, default=None, help="Ignore host if only this port is open (P1).")
    parser.add_argument("--skip-ping-sweep", action="store_true", help="Skip Phase 2.")
    parser.add_argument("--phase3", default="-p-", help="Phase 3 port spec or 'skip'.")
    parser.add_argument("-j", "--parallel-scans", type=int, default=20, help="Parallel threads for P4/P5.")
    parser.add_argument("-o", "--output-dir", default=".", help="Base output directory.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")
    parser.add_argument("-f", "--force-overwrite", action="store_true", help="Force overwrite existing files.")
    
    # Credential Args
    parser.add_argument("--smb-user", help="Username for SMB/MSSQL NSE scripts.")
    parser.add_argument("--smb-pass", help="Password for SMB/MSSQL NSE scripts.")
    parser.add_argument("--smb-domain", help="Domain for SMB/MSSQL NSE scripts.")
    
    # Work Hours Args
    parser.add_argument("--start-time", help="Start time for work window (HH:MM). Script runs after this time.")
    parser.add_argument("--end-time", help="End time for work window (HH:MM). Script pauses after this time.")

    args = parser.parse_args()

    # --- Interactive Prompts (if args missing) ---
    if args.scan_title is None: args.scan_title = prompt_user("Scan Title", validation_func=is_not_empty)
    if args.host_list is None: args.host_list = prompt_user("Host List File", validation_func=is_valid_path)
    
    # Interactive prompt for work hours if not provided in CLI
    if not args.start_time and not args.end_time:
        use_window = prompt_user("Restrict scanning to specific work hours? (y/N)", default="N", validation_func=is_yes_no)
        if use_window.lower().startswith('y'):
            args.start_time = prompt_user("Start Time (HH:MM, e.g. 09:00)", default="09:00", validation_func=is_valid_time_format)
            args.end_time = prompt_user("End Time (HH:MM, e.g. 17:00)", default="17:00", validation_func=is_valid_time_format)
    
    smb_creds = {
        'username': args.smb_user,
        'password': args.smb_pass,
        'domain': args.smb_domain
    }

    # Setup Directory & Logging
    main_scan_output_dir = Path(args.output_dir).resolve() / args.scan_title
    try:
        main_scan_output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print_red(f"Error creating dir {main_scan_output_dir}: {e}"); sys.exit(1)

    log_file_path = main_scan_output_dir / f"{args.scan_title}_main_scan.log"
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s',
        filename=log_file_path, filemode='a', force=True
    )
    log = logging.getLogger("Scanner")
    
    print_blue(f"--- Scan: {args.scan_title} ---")
    print_blue(f"--- Output: {main_scan_output_dir} ---")
    print_blue(f"--- Log: {log_file_path} ---")
    if args.start_time:
        print_blue(f"--- Work Window: {args.start_time} to {args.end_time} ---")

    targets = []
    try:
        with open(args.host_list, "r") as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        log.critical(f"Cannot read host list: {e}"); sys.exit(1)

    # --- Subnet Completion Log (Resume at Subnet Level) ---
    progress_log_file = main_scan_output_dir / "scan_progress_completed_subnets.log"
    completed_subnets = set()
    if progress_log_file.exists():
        try: completed_subnets = set(progress_log_file.read_text().splitlines())
        except: pass

    # --- Main Loop ---
    for i, target in enumerate(targets):
        if target in completed_subnets and not args.force_overwrite:
            print_green(f"Skipping completed subnet: {target}")
            continue

        result = process_single_target(target, args, main_scan_output_dir, log, smb_creds)
        
        # Mark subnet as complete if result returned (even if empty, it means we scanned it)
        if result is not None:
             with open(progress_log_file, "a") as f: f.write(target + "\n")

        gc.collect() # Clean up after each subnet
        
    print_green("\n--- ALL TASKS COMPLETE ---")
    log.info("Campaign Complete")
    logging.shutdown()

if __name__ == "__main__":
    main()
