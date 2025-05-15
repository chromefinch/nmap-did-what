import xml.etree.ElementTree as ET
import sqlite3
import argparse
import sys
import os
import json # Added for handling JSON data for script outputs

#
# Script to parse nmap xml files and populate an SQLite DB
# use with Grafana Dashboard - https://hackertarget.com/nmap-dashboard-with-grafana/
#

# Helper function to recursively parse structured Nmap script/table elements
def _parse_structured_xml_node(node):
    """
    Recursively parses an XML node (typically <script> or <table>)
    containing <elem> or nested <table> into a dictionary.
    """
    data = {}
    # Direct child 'elem' elements
    for elem in node.findall('elem'):
        key = elem.get('key')
        if key:
            # If multiple elements have the same key, store as a list
            if key in data:
                if not isinstance(data[key], list):
                    data[key] = [data[key]]
                data[key].append(elem.text)
            else:
                data[key] = elem.text
    # Direct child 'table' elements
    for table in node.findall('table'):
        key = table.get('key')
        table_data = _parse_structured_xml_node(table) # Recurse
        if key:
            # If multiple tables have the same key, store as a list
            if key in data:
                if not isinstance(data[key], list):
                    data[key] = [data[key]]
                data[key].append(table_data)
            else:
                data[key] = table_data
        else:
            # Handle table without a key by adding to a list of anonymous tables
            data.setdefault('anonymous_tables', []).append(table_data)
    return data


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

    scan_start_timestamp_ms = None
    scan_start_time_str = root.get('start')
    if scan_start_time_str is not None:
        try:
            scan_start_timestamp_ms = int(scan_start_time_str) * 1000 # Convert to milliseconds
        except ValueError:
            print(f"Warning: Could not parse scan start time '{scan_start_time_str}' as integer.", file=sys.stderr)

    elapsed_time = 'Unknown'
    runstats_elem = root.find('runstats')
    if runstats_elem is not None:
        finished_elem = runstats_elem.find('finished')
        if finished_elem is not None:
            elapsed_time = finished_elem.get('elapsed', 'Unknown')

    total_hosts_scanned = 0
    total_open_ports_found = 0

    hosts_data = []
    for host_elem in root.findall('host'):
        total_hosts_scanned += 1

        status_elem = host_elem.find('status')
        host_state = status_elem.get('state', 'unknown') if status_elem is not None else 'unknown'
        if host_state != 'up':
            continue

        ip_address = 'Unknown'
        mac_address = None
        mac_vendor = None
        for addr_elem in host_elem.findall('address'):
            addr_type = addr_elem.get('addrtype')
            if addr_type == 'ipv4':
                ip_address = addr_elem.get('addr', ip_address) # Keep first IPv4 if multiple
            elif addr_type == 'ipv6' and ip_address == 'Unknown': # Fallback to IPv6 if no IPv4
                ip_address = addr_elem.get('addr', 'Unknown')
            elif addr_type == 'mac':
                mac_address = addr_elem.get('addr')
                mac_vendor = addr_elem.get('vendor')
        if ip_address == 'Unknown' and host_elem.find("address") is not None: # Fallback any address
             ip_address = host_elem.find("address").get('addr', 'Unknown')


        hostname = 'Unknown'
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            user_hostname_elem = hostnames_elem.find("hostname[@type='user']")
            ptr_hostname_elem = hostnames_elem.find("hostname[@type='PTR']")
            any_hostname_elem = hostnames_elem.find('hostname')
            if user_hostname_elem is not None:
                hostname = user_hostname_elem.get('name', 'Unknown')
            elif ptr_hostname_elem is not None:
                hostname = ptr_hostname_elem.get('name', 'Unknown')
            elif any_hostname_elem is not None:
                hostname = any_hostname_elem.get('name', 'Unknown')

        os_name = 'Unknown'
        os_accuracy = None
        os_elem = host_elem.find('os')
        if os_elem is not None:
            best_osmatch_elem = None
            highest_accuracy = -1
            for osmatch_elem in os_elem.findall('osmatch'):
                current_accuracy = int(osmatch_elem.get('accuracy', '0'))
                if current_accuracy > highest_accuracy:
                    highest_accuracy = current_accuracy
                    best_osmatch_elem = osmatch_elem
            
            if best_osmatch_elem is not None:
                os_name = best_osmatch_elem.get('name', 'Unknown')
                os_accuracy = highest_accuracy
            # Fallback for OS info in service elements handled per-port

        uptime_seconds = None
        uptime_elem = host_elem.find('uptime')
        if uptime_elem is not None:
            try:
                uptime_seconds = int(uptime_elem.get('seconds'))
            except (ValueError, TypeError):
                pass # uptime_seconds remains None

        distance = None
        distance_elem = host_elem.find('distance')
        if distance_elem is not None:
            try:
                distance = int(distance_elem.get('value'))
            except (ValueError, TypeError):
                pass # distance remains None
        
        # --- Host Script Data ---
        host_scripts_dict = {}
        hostscript_section = host_elem.find('hostscript')
        if hostscript_section is not None:
            for script_elem in hostscript_section.findall('script'):
                script_id = script_elem.get('id')
                script_output_attr = script_elem.get('output')
                if not script_id:
                    continue

                structured_data = _parse_structured_xml_node(script_elem)
                if structured_data:
                    host_scripts_dict[script_id] = structured_data
                elif script_output_attr: # Fallback to raw output attribute
                    host_scripts_dict[script_id] = script_output_attr
        host_scripts_json = json.dumps(host_scripts_dict) if host_scripts_dict else None


        ports_tested_count = 0
        ports_open_count = 0
        ports_closed_count = 0
        ports_filtered_count = 0
        parsed_ports = []

        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port_elem in ports_elem.findall('port'):
                ports_tested_count += 1
                port_id = port_elem.get('portid', 'N/A')
                protocol = port_elem.get('protocol', 'N/A')

                state = 'N/A'
                reason = None
                state_elem = port_elem.find('state')
                if state_elem is not None:
                    state = state_elem.get('state', 'N/A')
                    reason = state_elem.get('reason')

                if state == 'open':
                    ports_open_count += 1
                    total_open_ports_found += 1
                elif state == 'closed':
                    ports_closed_count += 1
                elif state == 'filtered':
                    ports_filtered_count += 1

                service_name = None
                service_product = None
                service_version = None
                service_extrainfo = None
                service_ostype = None
                service_method = None
                service_conf = None
                http_title = None # Initialize for each port
                ssl_common_name = None
                ssl_issuer = None
                all_port_scripts_data = {} # Initialize for each port


                service_elem = port_elem.find('service')
                if service_elem is not None:
                    service_name = service_elem.get('name')
                    service_product = service_elem.get('product')
                    service_version = service_elem.get('version')
                    service_extrainfo = service_elem.get('extrainfo')
                    service_ostype = service_elem.get('ostype')
                    service_method = service_elem.get('method')
                    conf_str = service_elem.get('conf')
                    if conf_str:
                        try:
                            service_conf = int(conf_str)
                        except ValueError:
                            pass # service_conf remains None
                    if service_ostype and os_name == 'Unknown': # OS fallback
                        os_name = service_ostype

                # Script Info
                for script_elem in port_elem.findall('script'):
                    script_id = script_elem.get('id')
                    script_output_attr = script_elem.get('output')
                    if not script_id:
                        continue
                    
                    structured_data = _parse_structured_xml_node(script_elem)

                    if structured_data:
                        all_port_scripts_data[script_id] = structured_data
                        if script_id == 'http-title' and 'output' in structured_data : # http-title typically simple
                             http_title = str(structured_data['output']).strip() if isinstance(structured_data['output'], str) else script_output_attr.strip() if script_output_attr else None
                        elif script_id == 'ssl-cert':
                            subject = structured_data.get('subject', {})
                            issuer = structured_data.get('issuer', {})
                            if isinstance(subject, dict): ssl_common_name = subject.get('commonName')
                            if isinstance(issuer, dict):
                                issuer_cn = issuer.get('commonName', '')
                                issuer_org = issuer.get('organizationName', '')
                                ssl_issuer = f"{issuer_cn} {issuer_org}".strip() if issuer_cn or issuer_org else None
                    
                    elif script_output_attr: # Fallback to raw output attribute
                        all_port_scripts_data[script_id] = script_output_attr
                        if script_id == 'http-title':
                            http_title = script_output_attr.strip()
                
                # Ensure http_title is captured if it was only in output attribute and not parsed as structured
                if not http_title and 'http-title' in all_port_scripts_data and isinstance(all_port_scripts_data['http-title'], str):
                    http_title = all_port_scripts_data['http-title'].strip()


                parsed_ports.append({
                    'port': port_id,
                    'protocol': protocol,
                    'state': state,
                    'reason': reason,
                    'service_name': service_name,
                    'service_product': service_product,
                    'service_version': service_version,
                    'service_extrainfo': service_extrainfo,
                    'service_method': service_method,
                    'service_conf': service_conf,
                    'http_title': http_title,
                    'ssl_common_name': ssl_common_name,
                    'ssl_issuer': ssl_issuer,
                    'all_scripts_data': json.dumps(all_port_scripts_data) if all_port_scripts_data else None
                })

            extraports_elem = ports_elem.find('extraports')
            if extraports_elem is not None:
                extra_state = extraports_elem.get('state')
                try:
                    extra_count = int(extraports_elem.get('count', '0'))
                except ValueError: extra_count = 0
                ports_tested_count += extra_count
                if extra_state == 'closed': ports_closed_count += extra_count
                elif extra_state == 'filtered': ports_filtered_count += extra_count

        start_timestamp_ms_host = None
        end_timestamp_ms_host = None
        host_start_time_str = host_elem.get('starttime')
        host_end_time_str = host_elem.get('endtime')
        try:
            if host_start_time_str: start_timestamp_ms_host = int(host_start_time_str) * 1000
            if host_end_time_str: end_timestamp_ms_host = int(host_end_time_str) * 1000
        except ValueError:
            print(f"Warning: Could not parse host time for {ip_address}.", file=sys.stderr)

        hosts_data.append({
            'ip': ip_address,
            'hostname': hostname,
            'mac_address': mac_address,
            'mac_vendor': mac_vendor,
            'os': os_name,
            'os_accuracy': os_accuracy,
            'uptime_seconds': uptime_seconds,
            'distance': distance,
            'host_scripts_data': host_scripts_json,
            'ports_tested': ports_tested_count,
            'ports_open': ports_open_count,
            'ports_closed': ports_closed_count,
            'ports_filtered': ports_filtered_count,
            'start_time': start_timestamp_ms_host,
            'end_time': end_timestamp_ms_host,
            'ports': parsed_ports
        })

    scan_summary = {
        'nmap_version': nmap_version,
        'command_line': command_line,
        'start_time': scan_start_timestamp_ms,
        'elapsed_time': elapsed_time,
        'total_hosts': total_hosts_scanned,
        'total_up_hosts': len(hosts_data),
        'total_open_ports': total_open_ports_found
    }
    return scan_summary, hosts_data


def create_database(db_name):
    """Creates the SQLite database and tables if they don't exist."""
    try:
        with sqlite3.connect(db_name) as conn:
            c = conn.cursor()
            c.execute("PRAGMA foreign_keys = ON;")

            c.execute('''CREATE TABLE IF NOT EXISTS scans (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            nmap_version TEXT,
                            command_line TEXT,
                            start_time INTEGER, -- Unix timestamp (milliseconds)
                            elapsed_time TEXT,
                            total_hosts INTEGER,
                            total_up_hosts INTEGER,
                            total_open_ports INTEGER
                        )''')

            c.execute('''CREATE TABLE IF NOT EXISTS hosts (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            scan_id INTEGER,
                            ip TEXT,
                            hostname TEXT,
                            mac_address TEXT,
                            mac_vendor TEXT,
                            os TEXT,
                            os_accuracy INTEGER,
                            uptime_seconds INTEGER,
                            distance INTEGER,
                            host_scripts_data TEXT, -- JSON data for host scripts
                            ports_tested INTEGER,
                            ports_open INTEGER,
                            ports_closed INTEGER,
                            ports_filtered INTEGER,
                            start_time INTEGER, -- Unix timestamp (milliseconds)
                            end_time INTEGER,   -- Unix timestamp (milliseconds)
                            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                        )''')
            c.execute("CREATE INDEX IF NOT EXISTS idx_host_ip ON hosts (scan_id, ip)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_host_os ON hosts (os)") # Added index on OS
            c.execute("CREATE INDEX IF NOT EXISTS idx_host_mac ON hosts (mac_address)")


            c.execute('''CREATE TABLE IF NOT EXISTS ports (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            scan_id INTEGER, 
                            host_id INTEGER,
                            port TEXT,
                            protocol TEXT,
                            state TEXT,
                            reason TEXT, -- Reason for port state
                            service_name TEXT,
                            service_product TEXT,
                            service_version TEXT,
                            service_extrainfo TEXT,
                            service_method TEXT, -- e.g. 'probed', 'table'
                            service_conf INTEGER, -- 1-10 confidence
                            http_title TEXT,
                            ssl_common_name TEXT,
                            ssl_issuer TEXT,
                            all_scripts_data TEXT, -- JSON data for all port scripts
                            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
                            FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
                        )''')
            c.execute("CREATE INDEX IF NOT EXISTS idx_port_lookup ON ports (host_id, port, protocol)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_port_service ON ports (service_name)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_port_state ON ports (state)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_port_scan_id_port ON ports (scan_id, port)") # For scan-wide port search

            conn.commit()
            print(f"Database '{db_name}' initialized successfully.")
            return True
    except sqlite3.Error as e:
        print(f"Database error during creation: {e}", file=sys.stderr)
        return False

def insert_data(db_name, scan_summary, hosts_data):
    """Inserts the parsed scan data into the SQLite database."""
    if not scan_summary or not hosts_data: # Check if hosts_data is empty too
        print("No valid scan data or no 'up' hosts found for insertion.")
        return

    try:
        with sqlite3.connect(db_name) as conn:
            c = conn.cursor()
            c.execute("PRAGMA foreign_keys = ON;")

            c.execute("""
                INSERT INTO scans (nmap_version, command_line, start_time, elapsed_time, total_hosts, total_up_hosts, total_open_ports)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_summary['nmap_version'], scan_summary['command_line'], scan_summary['start_time'],
                scan_summary['elapsed_time'], scan_summary['total_hosts'], scan_summary['total_up_hosts'],
                scan_summary['total_open_ports']
            ))
            scan_id = c.lastrowid

            for host in hosts_data:
                c.execute("""
                    INSERT INTO hosts (scan_id, ip, hostname, mac_address, mac_vendor, os, os_accuracy, uptime_seconds, distance, host_scripts_data, ports_tested, ports_open, ports_closed, ports_filtered, start_time, end_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id, host['ip'], host['hostname'], host['mac_address'], host['mac_vendor'],
                    host['os'], host['os_accuracy'], host['uptime_seconds'], host['distance'],
                    host['host_scripts_data'], host['ports_tested'], host['ports_open'],
                    host['ports_closed'], host['ports_filtered'], host['start_time'], host['end_time']
                ))
                host_id = c.lastrowid

                for port_data in host['ports']: # Renamed 'port' to 'port_data' to avoid conflict
                    c.execute("""
                        INSERT INTO ports (scan_id, host_id, port, protocol, state, reason, 
                                           service_name, service_product, service_version, service_extrainfo, 
                                           service_method, service_conf, http_title, ssl_common_name, 
                                           ssl_issuer, all_scripts_data)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id, host_id, port_data['port'], port_data['protocol'], port_data['state'], port_data['reason'],
                        port_data['service_name'], port_data['service_product'], port_data['service_version'],
                        port_data['service_extrainfo'], port_data['service_method'], port_data['service_conf'],
                        port_data['http_title'], port_data['ssl_common_name'], port_data['ssl_issuer'],
                        port_data['all_scripts_data']
                    ))
            conn.commit()
            print(f"Successfully inserted data for scan ID {scan_id} into '{db_name}'.")
    except sqlite3.Error as e:
        print(f"Database error during insertion: {e}", file=sys.stderr)


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

    if not os.path.exists(xml_file):
        print(f"Error: Input XML file not found: {xml_file}", file=sys.stderr)
        sys.exit(1)

    if not create_database(db_name):
        print("Failed to initialize the database. Exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing Nmap XML file: {xml_file}...")
    scan_summary, hosts_data = parse_nmap_xml(xml_file)

    if scan_summary is None or hosts_data is None : # Check if hosts_data is None explicitly
        print("Failed to parse XML file or no data retrieved. Exiting.", file=sys.stderr)
        sys.exit(1)
    
    if not hosts_data and scan_summary is not None: # If summary is there but no hosts_data (e.g. no hosts were up)
        print("Parsing complete. No 'up' hosts found to insert into the database.")
        # Still insert the scan summary if desired, or exit.
        # For now, let's allow inserting a scan record even with 0 up hosts.
        # The insert_data function has a check for empty hosts_data as well.
        if scan_summary.get('total_up_hosts', 0) == 0:
             print("No up hosts were found in the scan to add to the database, but scan summary will be recorded.")


    print(f"Parsing complete. Found {scan_summary.get('total_up_hosts', 0)} up hosts.")

    print(f"Inserting data into database: {db_name}...")
    insert_data(db_name, scan_summary, hosts_data)

    print("Script finished.")

if __name__ == '__main__':
    main()
