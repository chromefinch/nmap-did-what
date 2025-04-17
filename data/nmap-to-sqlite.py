import xml.etree.ElementTree as ET
import sqlite3
import argparse
import sys # Added for error handling output
import os # Added for checking file existence

#
# Script to parse nmap xml files and populate an SQLite DB
# use with Grafana Dashboard - https://hackertarget.com/nmap-dashboard-with-grafana/
#

def parse_nmap_xml(xml_file):
    """Parses an Nmap XML file and extracts scan data."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except FileNotFoundError:
        print(f"Error: XML file not found at {xml_file}", file=sys.stderr)
        return None, None
    except ET.ParseError as e:
        print(f"Error: Failed to parse XML file {xml_file}. Reason: {e}", file=sys.stderr)
        return None, None

    nmap_version = root.get('version', 'Unknown')
    command_line = root.get('args', 'Unknown')

    scan_start_timestamp = None
    scan_start_time_str = root.get('start')
    # Nmap 'startstr' attribute provides a human-readable time if needed
    if scan_start_time_str is not None:
        try:
            # timestamps set to match native grafana format (milliseconds) OR NOT b/c that's stupid
            scan_start_timestamp = int(scan_start_time_str)
        except ValueError:
            print(f"Warning: Could not parse scan start time '{scan_start_time_str}' as integer.", file=sys.stderr)
            scan_start_timestamp = None # Keep it None if conversion fails

    elapsed_time = 'Unknown'
    runstats_elem = root.find('runstats')
    if runstats_elem is not None:
        finished_elem = runstats_elem.find('finished')
        if finished_elem is not None:
            elapsed_time = finished_elem.get('elapsed', 'Unknown')

    total_hosts_scanned = 0 # Counter for hosts found in the XML
    total_open_ports_found = 0 # Counter for open ports across all hosts

    hosts_data = []
    for host_elem in root.findall('host'):
        total_hosts_scanned += 1

        # --- Host Status ---
        status_elem = host_elem.find('status')
        host_state = status_elem.get('state', 'unknown') if status_elem is not None else 'unknown'
        # Skip hosts that are down
        if host_state != 'up':
            continue

        # --- Host Address and Name ---
        ip_address = 'Unknown'
        address_elem = host_elem.find("address[@addrtype='ipv4']") # Prioritize IPv4
        if address_elem is None:
            address_elem = host_elem.find("address[@addrtype='ipv6']") # Fallback IPv6
        if address_elem is None:
            address_elem = host_elem.find("address") # Fallback any address
        if address_elem is not None:
            ip_address = address_elem.get('addr', 'Unknown')

        hostname = 'Unknown'
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname[@type='user']") # User-provided name
            if hostname_elem is None:
                 hostname_elem = hostnames_elem.find("hostname[@type='PTR']") # PTR record
            if hostname_elem is None:
                hostname_elem = hostnames_elem.find('hostname') # Any hostname
            if hostname_elem is not None:
                hostname = hostname_elem.get('name', 'Unknown')


        # --- Host OS Detection ---
        os_name = 'Unknown'
        os_elem = host_elem.find('os')
        if os_elem is not None:
            osmatch_elem = os_elem.find('osmatch')
            if osmatch_elem is not None:
                # Could potentially grab accuracy os_match.get('accuracy')
                os_name = osmatch_elem.get('name', 'Unknown')
            else:
                # Sometimes OS info is in port 'service' element
                # Check ports later if still Unknown
                pass

        # --- Port Information ---
        ports_tested_count = 0
        ports_open_count = 0
        ports_closed_count = 0
        ports_filtered_count = 0
        parsed_ports = []

        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            # Process individual port entries
            for port_elem in ports_elem.findall('port'):
                ports_tested_count += 1
                port_id = port_elem.get('portid', 'N/A')
                protocol = port_elem.get('protocol', 'N/A')

                state_elem = port_elem.find('state')
                state = 'N/A'
                if state_elem is not None:
                    state = state_elem.get('state', 'N/A')
                    # reason = state_elem.get('reason', '') # Could store reason if needed

                if state == 'open':
                    ports_open_count += 1
                    total_open_ports_found += 1
                elif state == 'closed':
                    ports_closed_count += 1
                elif state == 'filtered':
                    ports_filtered_count += 1

                # Service Info
                service_name = None
                service_product = None
                service_version = None
                service_ostype = None
                service_info_str = ''
                http_title = None
                ssl_common_name = None
                ssl_issuer = None

                service_elem = port_elem.find('service')
                if service_elem is not None:
                    service_name = service_elem.get('name')
                    service_product = service_elem.get('product')
                    service_version = service_elem.get('version')
                    service_ostype = service_elem.get('ostype')
                    # Construct combined service info string
                    service_info_parts = [p for p in [service_product, service_version] if p]
                    service_info_str = ' '.join(service_info_parts)
                    # Update host OS if found via service and not already known
                    if service_ostype and os_name == 'Unknown':
                        os_name = service_ostype


                # Script Info (e.g., http-title, ssl-cert)
                for script_elem in port_elem.findall('script'):
                    script_id = script_elem.get('id')
                    script_output = script_elem.get('output')

                    if script_id == 'http-title' and script_output:
                        http_title = script_output.strip()
                    elif script_id == 'ssl-cert':
                        # Find subject and issuer tables within the script output
                        subject_table = script_elem.find("table[@key='subject']")
                        if subject_table is not None:
                            cn_elem = subject_table.find("elem[@key='commonName']")
                            if cn_elem is not None:
                                ssl_common_name = cn_elem.text

                        issuer_table = script_elem.find("table[@key='issuer']")
                        if issuer_table is not None:
                            # Use findtext for potentially missing elements, providing default ''
                            issuer_cn = issuer_table.findtext("elem[@key='commonName']", default='')
                            issuer_org = issuer_table.findtext("elem[@key='organizationName']", default='')
                            ssl_issuer = f"{issuer_cn} {issuer_org}".strip()


                parsed_ports.append({
                    'port': port_id,
                    'protocol': protocol,
                    'state': state,
                    'service_name': service_name,
                    'service_info': service_info_str,
                    'http_title': http_title,
                    'ssl_common_name': ssl_common_name,
                    'ssl_issuer': ssl_issuer
                })

            # Process extraports (ports summarised by Nmap, e.g., "995 closed ports")
            extraports_elem = ports_elem.find('extraports')
            if extraports_elem is not None:
                extra_state = extraports_elem.get('state')
                try:
                    extra_count = int(extraports_elem.get('count', '0'))
                except ValueError:
                    extra_count = 0

                ports_tested_count += extra_count # Add these to the total tested count
                if extra_state == 'closed':
                    ports_closed_count += extra_count
                elif extra_state == 'filtered':
                    ports_filtered_count += extra_count
                # Note: Nmap doesn't typically summarise 'open' ports in extraports

        # --- Host Timings ---
        start_timestamp_ms = None
        end_timestamp_ms = None
        host_start_time_str = host_elem.get('starttime')
        host_end_time_str = host_elem.get('endtime')
        try:
            if host_start_time_str:
                start_timestamp_ms = int(host_start_time_str) * 1000
            if host_end_time_str:
                end_timestamp_ms = int(host_end_time_str) * 1000
        except ValueError:
             print(f"Warning: Could not parse host time for {ip_address}.", file=sys.stderr)
             # Keep timestamps as None if conversion fails

        # Append collected host data
        hosts_data.append({
            'ip': ip_address,
            'hostname': hostname,
            'os': os_name,
            'ports_tested': ports_tested_count,
            'ports_open': ports_open_count,
            'ports_closed': ports_closed_count,
            'ports_filtered': ports_filtered_count,
            'start_time': start_timestamp_ms,
            'end_time': end_timestamp_ms,
            'ports': parsed_ports # List of dictionaries for ports
        })

    # Overall scan summary dictionary
    scan_summary = {
        'nmap_version': nmap_version,
        'command_line': command_line,
        'start_time': scan_start_timestamp, # In milliseconds for Grafana
        'elapsed_time': elapsed_time,
        'total_hosts': total_hosts_scanned, # Total found in XML
        'total_up_hosts': len(hosts_data), # Total actually processed (state='up')
        'total_open_ports': total_open_ports_found
    }

    return scan_summary, hosts_data


def create_database(db_name):
    """Creates the SQLite database and tables if they don't exist."""
    try:
        # Context manager ensures connection is closed
        with sqlite3.connect(db_name) as conn:
            c = conn.cursor()

            # Scans table - Added total_up_hosts
            c.execute('''CREATE TABLE IF NOT EXISTS scans (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            nmap_version TEXT,
                            command_line TEXT,
                            start_time INTEGER, -- Storing as Unix timestamp (milliseconds)
                            elapsed_time TEXT,
                            total_hosts INTEGER, -- Total hosts in the XML
                            total_up_hosts INTEGER, -- Total hosts with state 'up'
                            total_open_ports INTEGER -- Total open ports across all up hosts
                        )''')

            # Hosts table - OS field potentially longer
            c.execute('''CREATE TABLE IF NOT EXISTS hosts (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            scan_id INTEGER,
                            ip TEXT,
                            hostname TEXT,
                            os TEXT,
                            ports_tested INTEGER,
                            ports_open INTEGER,
                            ports_closed INTEGER,
                            ports_filtered INTEGER,
                            start_time INTEGER, -- Storing as Unix timestamp (milliseconds)
                            end_time INTEGER,   -- Storing as Unix timestamp (milliseconds)
                            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                        )''')
            # Added index for faster host lookup by IP within a scan
            c.execute("CREATE INDEX IF NOT EXISTS idx_host_ip ON hosts (scan_id, ip)")


            # Ports table - Added indexes
            c.execute('''CREATE TABLE IF NOT EXISTS ports (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            scan_id INTEGER, -- Denormalized for easier scan-wide port queries
                            host_id INTEGER,
                            port TEXT,       -- Storing as TEXT as it might contain non-numeric like 'unknown'
                            protocol TEXT,
                            state TEXT,
                            service_name TEXT,
                            service_info TEXT, -- Combined product/version
                            http_title TEXT,
                            ssl_common_name TEXT,
                            ssl_issuer TEXT,
                            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
                            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
                        )''')
            # Added indexes for faster port lookups
            c.execute("CREATE INDEX IF NOT EXISTS idx_port_lookup ON ports (host_id, port, protocol)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_port_service ON ports (service_name)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_port_state ON ports (state)")


            conn.commit() # Commit changes
            print(f"Database '{db_name}' initialized successfully.")
            return True # Indicate success
    except sqlite3.Error as e:
        print(f"Database error during creation: {e}", file=sys.stderr)
        return False # Indicate failure

def insert_data(db_name, scan_summary, hosts_data):
    """Inserts the parsed scan data into the SQLite database."""
    if not scan_summary or not hosts_data:
        print("No valid scan data provided for insertion.")
        return

    try:
        # Use context manager for the connection
        with sqlite3.connect(db_name) as conn:
            c = conn.cursor()
            c.execute("PRAGMA foreign_keys = ON;") # Ensure foreign key constraints are enforced

            # Insert scan summary
            c.execute("""
                INSERT INTO scans (nmap_version, command_line, start_time, elapsed_time, total_hosts, total_up_hosts, total_open_ports)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_summary['nmap_version'], scan_summary['command_line'], scan_summary['start_time'],
                scan_summary['elapsed_time'], scan_summary['total_hosts'], scan_summary['total_up_hosts'],
                scan_summary['total_open_ports']
            ))
            scan_id = c.lastrowid # Get the ID of the inserted scan record

            # Insert host data and associated port data
            for host in hosts_data:
                c.execute("""
                    INSERT INTO hosts (scan_id, ip, hostname, os, ports_tested, ports_open, ports_closed, ports_filtered, start_time, end_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id, host['ip'], host['hostname'], host['os'], host['ports_tested'],
                    host['ports_open'], host['ports_closed'], host['ports_filtered'],
                    host['start_time'], host['end_time']
                ))
                host_id = c.lastrowid # Get the ID of the inserted host record

                # Insert port data for this host
                for port in host['ports']:
                    c.execute("""
                        INSERT INTO ports (scan_id, host_id, port, protocol, state, service_name, service_info, http_title, ssl_common_name, ssl_issuer)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id, host_id, port['port'], port['protocol'], port['state'],
                        port['service_name'], port['service_info'], port['http_title'],
                        port['ssl_common_name'], port['ssl_issuer']
                    ))

            conn.commit() # Commit all insertions for this scan
            print(f"Successfully inserted data for scan ID {scan_id} into '{db_name}'.")

    except sqlite3.Error as e:
        print(f"Database error during insertion: {e}", file=sys.stderr)
        # Consider rolling back if necessary, though context manager handles closing


def main():
    parser = argparse.ArgumentParser(
        description="Parse Nmap XML output and store results in an SQLite database.",
        epilog="Example: python nmap_parser.py scan_results.xml -db nmap_data.sqlite"
        )
    parser.add_argument("xml_file", help="Path to the Nmap output XML file")
    parser.add_argument("-db", "--database", dest='db_name', default='nmap_results.db',
                        help="Path to the SQLite database file (default: nmap_results.db)")
    args = parser.parse_args()

    xml_file = args.xml_file
    db_name = args.db_name

    # Check if XML file exists before parsing
    if not os.path.exists(xml_file):
        print(f"Error: Input XML file not found: {xml_file}", file=sys.stderr)
        sys.exit(1) # Exit if file doesn't exist

    # Attempt to create/initialize the database first
    if not create_database(db_name):
        print("Failed to initialize the database. Exiting.", file=sys.stderr)
        sys.exit(1) # Exit if DB creation fails

    # Parse the XML file
    print(f"Parsing Nmap XML file: {xml_file}...")
    scan_summary, hosts_data = parse_nmap_xml(xml_file)

    # Check if parsing was successful
    if scan_summary is None or hosts_data is None:
        print("Failed to parse XML file. Exiting.", file=sys.stderr)
        sys.exit(1) # Exit if parsing fails

    print(f"Parsing complete. Found {scan_summary.get('total_up_hosts', 0)} up hosts.")

    # Insert the parsed data into the database
    print(f"Inserting data into database: {db_name}...")
    insert_data(db_name, scan_summary, hosts_data)

    print("Script finished.")

if __name__ == '__main__':
    main()
