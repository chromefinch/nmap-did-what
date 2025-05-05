import time
import ipaddress
import re
import sys
import os # Added for file size tracking (efficiency improvement)

def get_total_host_ips_from_file(subnet_file_path):
    """
    Calculates the total number of *host* IPs from a file containing subnets.
    Excludes network and broadcast addresses for standard IPv4 networks.
    """
    total_host_ips = 0
    try:
        with open(subnet_file_path, 'r') as f:
            subnets = [line.strip() for line in f if line.strip()]
        for subnet_str in subnets:
            try:
                network = ipaddress.ip_network(subnet_str, strict=False)
                # Iterate through host addresses and count them
                # This correctly handles IPv4 (excluding network/broadcast)
                # and IPv6 address counting.
                # For very large IPv6 ranges, this could be slow, but
                # accurate for the progress calculation logic.
                count = 0
                for _ in network.hosts():
                    count += 1
                total_host_ips += count
            except ValueError as e:
                print(f"\nWarning: Invalid subnet '{subnet_str}' in input file: {e}", file=sys.stderr)
    except FileNotFoundError:
        print(f"\nError: Subnet file not found at '{subnet_file_path}'.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"\nAn error occurred reading the subnet file: {e}", file=sys.stderr)
        return None
    return total_host_ips

def parse_gnmap_lines(lines, existing_open_hosts, existing_all_hosts):
    """Parses new lines from a .gnmap file content."""
    new_open_hosts = set()
    new_all_hosts = set()

    for line in lines:
        # Find all hosts reported
        if line.startswith("Host: "):
            parts = line.split()
            if len(parts) > 1:
                ip_address = parts[1]
                # Validate if it's potentially an IP address before adding
                try:
                    ipaddress.ip_address(ip_address) # Basic validation
                    new_all_hosts.add(ip_address)
                    # Check if this host has open ports in the same line
                    if "open" in line:
                        new_open_hosts.add(ip_address)
                except ValueError:
                    # Handle cases where Nmap might report a hostname that isn't an IP
                    # Or if the line format is unexpected.
                    # print(f"\nWarning: Could not parse IP from line: {line.strip()}", file=sys.stderr)
                    pass # Often Nmap might put (hostname) here, ignore for IP count

    # Update the main sets
    existing_all_hosts.update(new_all_hosts)
    existing_open_hosts.update(new_open_hosts)


def monitor_scan_progress():
    """
    Periodically polls an nmap .gnmap file for unique hosts and open ports,
    calculates the percentage complete based on *host* IPs, and shows status.
    More efficient file reading by checking only new content.
    """
    subnet_file = input("Please enter the path to the file containing the target subnets: ")
    # Use the revised function to get host count
    total_target_hosts = get_total_host_ips_from_file(subnet_file)

    if total_target_hosts is None:
        print("Could not determine the total number of target host IPs. Exiting.", file=sys.stderr)
        return
    if total_target_hosts == 0:
         print("Warning: Calculated total target hosts is 0. Progress might not be accurate.", file=sys.stderr)
         # Allow continuing, maybe the user provided single IPs or non-standard ranges

    gnmap_file = input("Please enter the path to the nmap .gnmap file: ")

    # Check if gnmap file exists initially
    if not os.path.exists(gnmap_file):
        print(f"Warning: .gnmap file '{gnmap_file}' not found yet. Waiting for it to be created...", file=sys.stderr)

    found_open_hosts = set()
    found_all_hosts = set()
    last_file_size = 0
    last_status_line_len = 0 # To help clear previous line properly

    try:
        while True:
            try:
                # Check if file exists now
                if not os.path.exists(gnmap_file):
                    # Display waiting message without progress if file still missing
                    status_line = f"\rWaiting for {gnmap_file}..."
                    print(status_line + ' ' * (last_status_line_len - len(status_line)), end='', flush=True)
                    last_status_line_len = len(status_line)
                    time.sleep(5)
                    continue # Skip the rest of the loop until file exists

                current_file_size = os.path.getsize(gnmap_file)

                # If file hasn't changed or shrunk (e.g., overwritten), process from start if needed
                # Simple approach: If size decreased, reset and re-read fully next time.
                # For this implementation, we'll just read new bytes. If the file is
                # completely replaced, seeking might fail, hence the outer try/except.
                # A robust solution might need more complex file handle management.
                if current_file_size > last_file_size:
                    with open(gnmap_file, 'r') as f:
                        f.seek(last_file_size)
                        new_lines = f.readlines()
                        parse_gnmap_lines(new_lines, found_open_hosts, found_all_hosts)
                    last_file_size = current_file_size
                elif current_file_size < last_file_size:
                    # File shrunk or was replaced? Reset and read all next time.
                    print("\nWarning: .gnmap file size decreased. Re-evaluating.", file=sys.stderr)
                    last_file_size = 0
                    found_open_hosts.clear()
                    found_all_hosts.clear()
                    # Rerun the loop to read from start
                    continue


            except FileNotFoundError:
                 # If the file disappears between the os.path.exists and os.path.getsize/open
                status_line = f"\rWaiting for {gnmap_file}..."
                print(status_line + ' ' * (last_status_line_len - len(status_line)), end='', flush=True)
                last_status_line_len = len(status_line)
                last_file_size = 0 # Reset size tracking
                time.sleep(5)
                continue
            except Exception as e:
                print(f"\nError reading or parsing {gnmap_file}: {e}", file=sys.stderr)
                # Decide whether to continue or exit, here we'll wait and retry
                time.sleep(5)
                continue

            # Calculate progress
            num_found_hosts = len(found_all_hosts)
            num_open_ports_hosts = len(found_open_hosts)

            # Prevent division by zero if total_target_hosts ended up as 0
            if total_target_hosts > 0:
                 percent_complete = (num_found_hosts / total_target_hosts) * 100
            elif num_found_hosts > 0:
                 percent_complete = 100.0 # If no target hosts expected, but found some, call it 100%? Or handle as error?
            else:
                 percent_complete = 0.0 # No targets expected, none found yet.

            # Ensure percentage doesn't exceed 100 due to potential edge cases
            percent_complete = min(percent_complete, 100.0)

            status_line = f"\rScanned {num_found_hosts}/{total_target_hosts} hosts. {num_open_ports_hosts} with open ports. Progress: {percent_complete:.2f}%"
            # Clear previous line completely by overwriting with spaces
            print(status_line + ' ' * (last_status_line_len - len(status_line)), end='', flush=True)
            last_status_line_len = len(status_line) # Store current length

            # Optional: Add a condition to break if 100% is reached and file hasn't changed recently
            # This requires tracking last modification time as well. For simplicity, we rely on Ctrl+C.

            time.sleep(5) # Check every 5 seconds

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
        # Print final status
        num_found_hosts = len(found_all_hosts)
        num_open_ports_hosts = len(found_open_hosts)
        if total_target_hosts > 0:
             percent_complete = min((num_found_hosts / total_target_hosts) * 100, 100.0)
        else:
            percent_complete = 0.0 # Or handle as appropriate
        print(f"Final count: Scanned {num_found_hosts}/{total_target_hosts} hosts. {num_open_ports_hosts} with open ports. Final Progress: {percent_complete:.2f}%")

    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)

if __name__ == "__main__":
    monitor_scan_progress()