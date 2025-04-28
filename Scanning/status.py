import time
import ipaddress
import re

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
                print(f"Warning: Invalid subnet '{subnet_str}' in input file.")
    except FileNotFoundError:
        print(f"Error: Subnet file not found at '{subnet_file_path}'.")
        return None
    except Exception as e:
        print(f"An error occurred reading the subnet file: {e}")
        return None
    return total_ips

def get_host_port_status_from_gnmap(gnmap_file_path, existing_data=None):
    """
    Parses an nmap .gnmap file and returns a dictionary of host information,
    including whether they have open ports.
    """
    if existing_data is None:
        host_data = {}  # {ip_address: {'up': True/False, 'open_ports': False}}
    else:
        host_data = existing_data

    try:
        with open(gnmap_file_path, 'r') as f:
            for line in f:
                if line.startswith("Host: "):
                    parts = line.split()
                    ip_address = parts[1]
                    status = parts[2]  # Usually 'up' or 'down'
                    if ip_address not in host_data:
                        host_data[ip_address] = {'up': False, 'open_ports': False}
                    host_data[ip_address]['up'] = (status == 'up')
                elif line.startswith("Ports: "):
                    match = re.search(r"Host: (\S+)", line)
                    if match:
                        ip_address = match.group(1)
                        if ip_address in host_data and host_data[ip_address]['up']:
                            if "open" in line:
                                host_data[ip_address]['open_ports'] = True
    except FileNotFoundError:
        print(f"Warning: .gnmap file not found at '{gnmap_file_path}'.")
    except Exception as e:
        print(f"An error occurred reading the .gnmap file: {e}")
    return host_data

def monitor_scan_progress():
    """
    Periodically polls an nmap .gnmap file for unique hosts and open ports,
    calculates the percentage complete, and shows the count of hosts with open ports.
    """
    subnet_file = input("Please enter the path to the file containing the target subnets: ")
    total_ips = get_total_ips_from_file(subnet_file)

    if total_ips is None or total_ips == 0:
        print("Could not determine the total number of target IPs. Exiting.")
        return

    gnmap_file = input("Please enter the path to the nmap .gnmap file: ")
    host_info = {}

    try:
        while True:
            current_host_info = get_host_port_status_from_gnmap(gnmap_file, host_info)
            if current_host_info is not None:
                host_info.update(current_host_info)
                num_found_hosts = len(host_info)
                num_open_ports = sum(1 for data in host_info.values() if data['up'] and data['open_ports'])
                percent_complete = (num_found_hosts / total_ips) * 100 if total_ips > 0 else 0
                print(f"Found {num_found_hosts} unique hosts, {num_open_ports} with open ports. Progress: {percent_complete:.2f}%")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    monitor_scan_progress()
