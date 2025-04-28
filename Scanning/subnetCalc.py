#!/usr/bin/env python3

import ipaddress

def calculate_total_ips_from_file():
    """
    Prompts the user for a file containing a list of IP subnets,
    calculates the number of IPs in each subnet, and returns the total.
    """
    while True:
        file_path = input("Please enter the path to the file containing IP subnets (one per line): ")
        try:
            with open(file_path, 'r') as f:
                subnets = [line.strip() for line in f if line.strip()]
            break
        except FileNotFoundError:
            print(f"Error: File not found at '{file_path}'. Please try again.")
        except Exception as e:
            print(f"An error occurred while reading the file: {e}. Please check the file and try again.")

    total_ips = 0
    for subnet_str in subnets:
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            num_ips = network.num_addresses
            total_ips += num_ips
            print(f"Subnet: {subnet_str}, Number of IPs: {num_ips}")
        except ValueError:
            print(f"Warning: Invalid IP subnet format '{subnet_str}'. Skipping.")

    print(f"\nTotal number of IPs across all subnets: {total_ips}")
    return total_ips

if __name__ == "__main__":
    calculate_total_ips_from_file()
