#!/usr/bin/env python3
# Robust Network Scanner with Phases 1-5
# Phase 4: Service Detection
# Phase 5: Safe Targeted NSE Scripts

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
import xml.etree.ElementTree as ET

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

# --- GNMAP Parsing ---
def parse_gnmap_live_hosts(gnmap_content):
    global log
    live_hosts = set()
    up_host_pattern = re.compile(r"^Host:\s+([\d.:a-fA-F]+)\s+(?:\(.*\)\s+)?Status:\s+Up", re.MULTILINE)
    for match in up_host_pattern.finditer(gnmap_content):
        ip = match.group(1); live_hosts.add(ip)
    return live_hosts

def parse_gnmap_ports_for_host(gnmap_content, target_ip):
    global log
    ports = set()
    host_line_pattern = re.compile(
        r"^Host:\s+" + re.escape(target_ip) + r"\s*(?:\(.*\)\s*)?.*?\sPorts:\s+(.*)", re.MULTILINE
    )
    port_pattern = re.compile(r"(\d+)/(?:open|open\|filtered)")
    match = host_line_pattern.search(gnmap_content)
    if match:
        ports.update(port_pattern.findall(match.group(1)))
    return sorted([int(p) for p in ports])

def parse_gnmap_filter_no_open(gnmap_content, ignore_port=None):
    global log
    potentially_live_hosts = set()
    up_host_pattern = re.compile(r"^Host:\s+([\d.:a-fA-F]+)\s+(?:\(.*\)\s+)?Status:\s+Up", re.MULTILINE)
    all_up_hosts = {match.group(1) for match in up_host_pattern.finditer(gnmap_content)}

    for ip in all_up_hosts:
        open_ports = parse_gnmap_ports_for_host(gnmap_content, ip)
        if not open_ports: continue
        if ignore_port is not None:
            try: ignore_port_int = int(ignore_port)
            except ValueError: ignore_port_int = -1 
            if len(open_ports) == 1 and open_ports[0] == ignore_port_int: continue
        potentially_live_hosts.add(ip)
    return potentially_live_hosts

def parse_gnmap_all_open_ports(gnmap_content):
    port_pattern = re.compile(r"(\d+)/(?:open|open\|filtered)")
    ports = set(port_pattern.findall(gnmap_content))
    return sorted([int(p) for p in ports])

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
    except ET.ParseError as e:
        log.error(f"XML Parse Error in {xml_file_path}: {e}")
    except Exception as e:
        log.error(f"General error parsing XML {xml_file_path}: {e}")
    
    return detected_services

# --- Phase 4: Deep Scan Task ---
def run_deep_scan(ip_to_scan, output_dir_path, sanitized_scan_title_as_prefix, gnmap_content_for_ports):
    global log
    ip_sanitized_for_filename = ip_to_scan.replace(':', '_').replace('.', '-') 
    file_basename = f"{sanitized_scan_title_as_prefix}_phase4_DeepScan_HOST_{ip_sanitized_for_filename}"
    nmap_output_prefix_abs = output_dir_path / file_basename 
    xml_file_abs = nmap_output_prefix_abs.with_suffix(".xml")

    if xml_file_abs.exists(): 
        return ip_to_scan, "skipped_exists", f"Output exists ({xml_file_abs.name})", xml_file_abs

    ports_to_scan = parse_gnmap_ports_for_host(gnmap_content_for_ports, ip_to_scan)
    if not ports_to_scan:
        return ip_to_scan, "skipped_no_ports", "No open ports found", None

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

    # --- NSE SELECTION LOGIC (Based on User Snippet) ---
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
    
    if output_prefix.with_suffix(".xml").exists():
        return ip_to_scan, port_to_scan, "skipped_exists", "Output exists"

    # Construct Nmap Command
    # -Pn: Treat as up, -n: No DNS, -p: Port, --script-timeout: Safety
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


def process_single_target(target_subnet_or_ip, cli_args, main_output_dir_path, current_log_instance, smb_creds):
    global log
    log = current_log_instance 

    sanitized_target_name = re.sub(r'[^\w\-.]', '_', target_subnet_or_ip) 
    sanitized_scan_title = re.sub(r'[^\w\-.]', '_', cli_args.scan_title)
    
    print_blue(f"\n--- Starting Analysis of {target_subnet_or_ip} ---")
    log.info(f"Target Start: {target_subnet_or_ip}")

    results_agg = {
        "phase3_target_ips": [], "open_ports_found": set(), "phase4_target_ips": [],
        "phase4_summary": {'success': 0, 'skipped_exists': 0, 'skipped_no_ports': 0, 'warning_down': 0, 'failed': 0},
        "phase5_summary": {'success': 0, 'skipped_exists': 0, 'skipped_no_script': 0, 'failed': 0}
    }

    # --- Phase 1: Discovery ---
    phase1_basename = f"{sanitized_scan_title}_{sanitized_target_name}_phase1_Top{cli_args.top_ports}Ports"
    phase1_xml = main_output_dir_path / f"{phase1_basename}.xml"
    phase1_gnmap = main_output_dir_path / f"{phase1_basename}.gnmap"
    phase1_content = None

    if not cli_args.force_overwrite and phase1_xml.exists():
        print_purple(f"[*] Phase 1 Skipped: {phase1_xml.name} exists.")
        try: phase1_content = phase1_gnmap.read_text()
        except Exception as e: print_red(f"[!] Read Err: {e}"); return None
    else:
        # Note: --max-retries 1 for speed on /8
        p1_cmd = ["nmap", "-sS", "-T4", "--max-retries", "1", "--max-rtt-timeout", "300ms", "--host-timeout", "3m", "-n", "-Pn", target_subnet_or_ip, "--top-ports", str(cli_args.top_ports), "-oA", str(main_output_dir_path / phase1_basename)]
        try:
            run_command(p1_cmd, cwd=str(main_output_dir_path), description=f"Phase 1: Discovery {target_subnet_or_ip}")
            if phase1_gnmap.exists(): phase1_content = phase1_gnmap.read_text()
            else: log.error("Phase 1 output missing"); return None
        except Exception as e: log.error(f"Phase 1 failed: {e}"); return None

    phase1_filtered_ips = parse_gnmap_filter_no_open(phase1_content, cli_args.ignore_port)
    print_green(f"    Phase 1: {len(phase1_filtered_ips)} hosts active (filtered).")

    # --- Phase 2: Ping Sweep (Optional) ---
    phase2_live_ips = set()
    if not cli_args.skip_ping_sweep:
        p2_basename = f"{sanitized_scan_title}_{sanitized_target_name}_phase2_PingSweep"
        p2_xml = main_output_dir_path / f"{p2_basename}.xml"
        p2_gnmap = main_output_dir_path / f"{p2_basename}.gnmap"
        
        if not cli_args.force_overwrite and p2_xml.exists():
            print_purple(f"[*] Phase 2 Skipped: {p2_xml.name} exists.")
            try: phase2_live_ips = parse_gnmap_live_hosts(p2_gnmap.read_text())
            except: pass
        else:
            p2_cmd = ["nmap", "-sn", "-T4", "-n", target_subnet_or_ip, "-oA", str(main_output_dir_path / p2_basename)]
            try:
                run_command(p2_cmd, cwd=str(main_output_dir_path), description=f"Phase 2: Ping Sweep {target_subnet_or_ip}")
                if p2_gnmap.exists(): phase2_live_ips = parse_gnmap_live_hosts(p2_gnmap.read_text())
            except Exception as e: log.error(f"Phase 2 failed: {e}")
        print_green(f"    Phase 2: {len(phase2_live_ips)} hosts up.")

    # --- Combine Targets for Phase 3 ---
    ips_for_phase3 = sorted(list(phase1_filtered_ips.union(phase2_live_ips)))
    results_agg["phase3_target_ips"].extend(ips_for_phase3)
    if not ips_for_phase3:
        print_red("[!] No live IPs found. Skipping subsequent phases.")
        return results_agg

    # --- Phase 3: Port Discovery ---
    phase3_content = None
    if cli_args.phase3.lower() != 'skip':
        p3_basename = f"{sanitized_scan_title}_{sanitized_target_name}_phase3_PortDisco"
        p3_xml = main_output_dir_path / f"{p3_basename}.xml"
        p3_gnmap = main_output_dir_path / f"{p3_basename}.gnmap"

        if not cli_args.force_overwrite and p3_xml.exists():
            print_purple(f"[*] Phase 3 Skipped: {p3_xml.name} exists.")
            try: phase3_content = p3_gnmap.read_text()
            except: pass
        else:
            # Create temp target file
            p3_targets_file = main_output_dir_path / f"{p3_basename}_targets.tmp"
            with open(p3_targets_file, 'w') as f: f.write("\n".join(ips_for_phase3))
            
            p3_args = shlex.split(cli_args.phase3) if cli_args.phase3 != "-p-" else ["-p-"]
            p3_cmd = ["nmap", "-sS", "-Pn", "-n", "-T4", "--min-rate", "800", "-iL", str(p3_targets_file)] + p3_args + ["-oA", str(main_output_dir_path / p3_basename)]
            
            try:
                run_command(p3_cmd, cwd=str(main_output_dir_path), description=f"Phase 3: Port Scan on {len(ips_for_phase3)} IPs")
                if p3_gnmap.exists(): phase3_content = p3_gnmap.read_text()
            except Exception as e: log.error(f"Phase 3 failed: {e}")
            finally: 
                if p3_targets_file.exists(): p3_targets_file.unlink()

    # --- Phase 4 Prep ---
    source_content = phase3_content if phase3_content else phase1_content
    source_name = "Phase 3" if phase3_content else "Phase 1"
    
    if not source_content:
        print_red("[!] No GNMAP data available for Phase 4.")
        return results_agg

    results_agg["open_ports_found"].update(parse_gnmap_all_open_ports(source_content))
    ips_for_p4 = []
    for ip in ips_for_phase3:
        if parse_gnmap_ports_for_host(source_content, ip): ips_for_p4.append(ip)
    
    results_agg["phase4_target_ips"].extend(ips_for_p4)
    
    # --- Phase 4: Deep Service Scan ---
    phase4_xml_files = [] # Keep track of generated XMLs for Phase 5
    if ips_for_p4:
        print_blue(f"\n[+] Phase 4: Deep Service Scan on {len(ips_for_p4)} IPs ({source_name} results)")
        
        # Function wrapper to return file paths
        scan_func = partial(run_deep_scan, 
                            output_dir_path=main_output_dir_path, 
                            sanitized_scan_title_as_prefix=sanitized_scan_title,
                            gnmap_content_for_ports=source_content)

        completed = 0
        total = len(ips_for_p4)
        
        with ThreadPoolExecutor(max_workers=cli_args.parallel_scans) as executor:
            futures = {executor.submit(scan_func, ip): ip for ip in ips_for_p4}
            for future in as_completed(futures):
                completed += 1
                ip = futures[future]
                try:
                    res_ip, status, msg, xml_path = future.result()
                    results_agg["phase4_summary"][status] = results_agg["phase4_summary"].get(status, 0) + 1
                    
                    if xml_path and (status == "success" or status == "skipped_exists"):
                        phase4_xml_files.append(xml_path)

                    # Simple Progress
                    if completed % 5 == 0 or completed == total:
                        print(f"\r    Progress: {completed}/{total} ({int(completed/total*100)}%)", end="")
                        sys.stdout.flush()
                except Exception as e:
                    log.error(f"Phase 4 Future Err {ip}: {e}")
                    results_agg["phase4_summary"]['failed'] += 1
        print() # Newline after progress
    else:
        print_yellow("    Skipping Phase 4: No IPs with open ports.")

    # --- Phase 5: Targeted NSE Scans ---
    # 1. Parse Phase 4 XMLs to find Services
    nse_targets = []
    print_blue("\n[+] Phase 5: Identifying Targeted NSE Candidates...")
    for xml_f in phase4_xml_files:
        services = parse_xml_services(xml_f)
        nse_targets.extend(services)
    
    if nse_targets:
        print_green(f"    Found {len(nse_targets)} service/port combinations to check with NSE.")
        print_blue(f"    Running Phase 5 Targeted Scans ({cli_args.parallel_scans} threads)...")
        
        nse_func = partial(run_targeted_nse, 
                           output_dir_path=main_output_dir_path,
                           sanitized_scan_title_as_prefix=sanitized_scan_title,
                           smb_creds=smb_creds)
        
        completed_nse = 0
        total_nse = len(nse_targets)
        
        with ThreadPoolExecutor(max_workers=cli_args.parallel_scans) as executor:
            futures = {executor.submit(nse_func, tgt): tgt for tgt in nse_targets}
            for future in as_completed(futures):
                completed_nse += 1
                try:
                    ip, port, status, msg = future.result()
                    results_agg["phase5_summary"][status] = results_agg["phase5_summary"].get(status, 0) + 1
                    
                    if status == "success":
                        log.info(f"P5 Success: {ip}:{port} -> {msg}")
                    elif status == "failed":
                        print_red(f"    P5 Fail: {ip}:{port} - {msg}")

                    if completed_nse % 5 == 0 or completed_nse == total_nse:
                         print(f"\r    NSE Progress: {completed_nse}/{total_nse} ({int(completed_nse/total_nse*100)}%)", end="")
                         sys.stdout.flush()
                except Exception as e:
                    log.error(f"Phase 5 Future Err: {e}")
        print()
        
        # Summary Print
        print_blue("    Phase 5 Summary:")
        for k, v in results_agg["phase5_summary"].items():
            if v > 0: print(f"      {k}: {v}")

    else:
        print_yellow("    Skipping Phase 5: No services identified from Phase 4.")

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

    args = parser.parse_args()

    # --- Interactive Prompts (if args missing) ---
    if args.scan_title is None: args.scan_title = prompt_user("Scan Title", validation_func=is_not_empty)
    if args.host_list is None: args.host_list = prompt_user("Host List File", validation_func=is_valid_path)
    
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

    targets = []
    try:
        with open(args.host_list, "r") as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        log.critical(f"Cannot read host list: {e}"); sys.exit(1)

    # --- Main Loop ---
    for i, target in enumerate(targets):
        process_single_target(target, args, main_scan_output_dir, log, smb_creds)
        
    print_green("\n--- ALL TASKS COMPLETE ---")
    log.info("Campaign Complete")
    logging.shutdown()

if __name__ == "__main__":
    main()
