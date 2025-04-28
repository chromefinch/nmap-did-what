import time
import ipaddress
import re
import sys

def get_total_ips_from_file(subnet_file_path):
    """Calculates the total number of IPs from a file containing subnets."""
    total_ips = 0
    try:
        with open(subnet_file_path, 'r') as f:
            subnets = [line.strip() for line in f if line.strip()]
        for subnet_str in subnets:
            try:
                network = ipaddress.ip_network(subnet_str, strict=False)
                total_ips += network.num_addresses
            except ValueError:
                print(f"Warning: Invalid subnet '{subnet_str}' in input file.", file=sys.stderr)
    except FileNotFoundError:
        print(f"Error: Subnet file not found at '{subnet_file_path}'.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An error occurred reading the subnet file: {e}", file=sys.stderr)
        return None
    return total_ips

def get_host_port_status_from_gnmap(gnmap_file_path, existing_open_hosts=None):
    """
    Parses an nmap .gnmap file and returns a set of unique host IPs
    that have at least one open port.
    """
    if existing_open_hosts is None:
        open_hosts = set()
    else:
        open_hosts = existing_open_hosts

    try:
        with open(gnmap_file_path, 'r') as f:
            for line in f:
                if "open" in line and "Host: " in line:
                    match = re.search(r"Host: (\S+)", line)
                    if match:
                        ip_address = match.group(1)
                        open_hosts.add(ip_address)
    except FileNotFoundError:
        print(f"Warning: .gnmap file not found at '{gnmap_file_path}'.", file=sys.stderr)
    except Exception as e:
        print(f"An error occurred reading the .gnmap file: {e}", file=sys.stderr)
    return open_hosts

def get_all_hosts_from_gnmap(gnmap_file_path, existing_hosts=None):
    """Parses an nmap .gnmap file and returns a set of all unique host IPs."""
    if existing_hosts is None:
        all_hosts = set()
    else:
        all_hosts = existing_hosts

    try:
        with open(gnmap_file_path, 'r') as f:
            for line in f:
                if line.startswith("Host: "):
                    parts = line.split()
                    ip_address = parts[1]
                    all_hosts.add(ip_address)
    except FileNotFoundError:
        print(f"Warning: .gnmap file not found at '{gnmap_file_path}'.", file=sys.stderr)
    except Exception as e:
        print(f"An error occurred reading the .gnmap file: {e}", file=sys.stderr)
    return all_hosts

def monitor_scan_progress():
    """
    Periodically polls an nmap .gnmap file for unique hosts and open ports,
    calculates the percentage complete, and shows the count of hosts with open ports.
    It clears the previous status line before updating.
    """
    subnet_file = input("Please enter the path to the file containing the target subnets: ")
    total_ips = get_total_ips_from_file(subnet_file)

    if total_ips is None or total_ips == 0:
        print("Could not determine the total number of target IPs. Exiting.", file=sys.stderr)
        return

    gnmap_file = input("Please enter the path to the nmap .gnmap file: ")
    found_open_hosts = set()
    found_all_hosts = set()

    try:
        while True:
            current_open_hosts = get_host_port_status_from_gnmap(gnmap_file, found_open_hosts)
            if current_open_hosts is not None:
                found_open_hosts.update(current_open_hosts)

            current_all_hosts = get_all_hosts_from_gnmap(gnmap_file, found_all_hosts)
            if current_all_hosts is not None:
                found_all_hosts.update(current_all_hosts)
                num_found_hosts = len(found_all_hosts)
                num_open_ports_hosts = len(found_open_hosts)
                percent_complete = (num_found_hosts / total_ips) * 100 if total_ips > 0 else 0
                status_line = f"\rFound {num_found_hosts} unique hosts, {num_open_ports_hosts} with open ports. Progress: {percent_complete:.2f}%"
                print(status_line, end='', flush=True)
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)

if __name__ == "__main__":
    monitor_scan_progress()
