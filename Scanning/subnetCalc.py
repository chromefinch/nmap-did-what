import ipaddress

def calculate_ips_from_file(file_path):
    """
    Reads a file containing subnets, calculates the total number of IPs,
    and returns the result.

    Args:
        file_path (str): Path to the file containing subnets in CIDR notation.

    Returns:
        int: Total number of IPs across all subnets in the file.
    """
    total_ips = 0
    
    try:
        with open(file_path, 'r') as file:
            # Read subnets line by line from the file
            subnets = file.readlines()
            # Remove newline characters and whitespace from each subnet
            subnets = [subnet.strip() for subnet in subnets]
            
            for subnet in subnets:
                # Create an IPv4 or IPv6 network object
                network = ipaddress.ip_network(subnet, strict=False)
                # Add the number of IP addresses in the subnet to the total
                total_ips += network.num_addresses

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except ValueError:
        print(f"Error: One or more subnets in the file are invalid.")

    return total_ips

# Example usage
file_path = 'subnets.txt'  # Replace with your file path
total = calculate_ips_from_file(file_path)
print(f"Total number of IPs: {total}")
