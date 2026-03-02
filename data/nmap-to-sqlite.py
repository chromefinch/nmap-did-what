import xml.etree.ElementTree as ET
import json
import sys # For accessing command-line arguments
import sqlite3 # Added for database interactions

def _parse_table_node(table_node):
    """
    Recursively parses a <table> node and its children (elem, table).
    A table can have a 'key' attribute.
    It can contain <elem> tags and nested <table> tags.
    """
    table_content = {}  # This will store the final parsed data for this table node
    
    # Data extracted from direct children of this table node
    direct_elements = {}
    unkeyed_direct_elements = []
    nested_tables_list = []

    # Parse direct <elem> children of this <table>
    for elem_node in table_node.findall('elem'):
        key = elem_node.get('key')
        value = elem_node.text
        if key:
            direct_elements[key] = value
        elif value: # Unkeyed <elem> with text content
            unkeyed_direct_elements.append(value)

    # Parse nested <table> children of this <table>
    for sub_table_node in table_node.findall('table'):
        parsed_sub_table = _parse_table_node(sub_table_node) # Recursive call
        if parsed_sub_table: # Only add if parsing returned something
            nested_tables_list.append(parsed_sub_table)

    # Get the key of the current table, if it exists
    table_key = table_node.get('key')

    if table_key:
        # If the table has a key, its content (elements and sub-tables)
        # goes into a dictionary under this key.
        current_table_data_under_key = {}
        if direct_elements:
            current_table_data_under_key.update(direct_elements)
        if unkeyed_direct_elements:
            # Store unkeyed elements under a special '_values' key if other keyed elements exist,
            # or directly if no other keyed elements.
            if current_table_data_under_key:
                 current_table_data_under_key['_unkeyed_values'] = unkeyed_direct_elements
            else: # Only unkeyed elements in this keyed table
                 current_table_data_under_key = {'_values': unkeyed_direct_elements}


        if nested_tables_list:
            current_table_data_under_key['tables'] = nested_tables_list
        
        table_content[table_key] = current_table_data_under_key
    else:
        # If the table has no key, its direct elements are merged.
        if direct_elements:
            table_content.update(direct_elements)
        
        if unkeyed_direct_elements:
            if table_content: # if there were already keyed elements merged
                table_content['_unkeyed_values'] = unkeyed_direct_elements
            else: # only unkeyed elements in this unkeyed table
                table_content['_values'] = unkeyed_direct_elements


        # And its nested tables are stored in a 'tables' list.
        if nested_tables_list:
            table_content['tables'] = nested_tables_list
            
    return table_content

def _parse_script_node(script_node):
    """
    Helper to parse a <script> node, including its direct <elem> children
    and <table> children.
    """
    script_info = {
        'id': script_node.get('id'),
        'output': script_node.get('output')
    }
    
    # Parse direct <elem> children of the <script> tag
    direct_elements = {}
    unkeyed_direct_elements = []
    
    for elem_node in script_node.findall('elem'):
        key = elem_node.get('key')
        value = elem_node.text
        if key:
            direct_elements[key] = value
        elif value: # Elem without a key, but with text content
            unkeyed_direct_elements.append(value)
            
    if direct_elements:
        script_info['elements'] = direct_elements
        if unkeyed_direct_elements: # If there were also unkeyed direct elements
            script_info['elements']['_unkeyed_values'] = unkeyed_direct_elements
    elif unkeyed_direct_elements: # Only unkeyed direct elements found
         script_info['elements'] = {'_values': unkeyed_direct_elements}

    # Parse <table> children of the <script> tag
    tables_data = []
    for table_node in script_node.findall('table'):
        parsed_table = _parse_table_node(table_node)
        if parsed_table: # Only add if parsing returned something non-empty
            tables_data.append(parsed_table)
    
    if tables_data:
        script_info['tables'] = tables_data
        
    return script_info

def parse_nmap_xml(xml_file):
    """
    Parses an Nmap XML file and extracts detailed host and service information,
    including comprehensive script outputs.
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML file '{xml_file}': {e}", file=sys.stderr)
        return None
    except FileNotFoundError:
        print(f"Error: File not found: '{xml_file}'", file=sys.stderr)
        return None

    # --- Extract metadata needed for deduplication ---
    scan_data = {
        'start_time': root.get('start'),
        'command_line': root.get('args'),
        'hosts': []
    }

    hosts_data = []

    for host_node in root.findall('host'):
        host_info = {}

        # --- Host Status ---
        status_node = host_node.find('status')
        if status_node is not None:
            host_info['status'] = {
                'state': status_node.get('state'),
                'reason': status_node.get('reason'),
                'reason_ttl': status_node.get('reason_ttl')
            }

        # --- Address Information (IPv4, IPv6, MAC) ---
        addresses = []
        for addr_node in host_node.findall('address'):
            addr_info = {
                'address': addr_node.get('addr'),
                'type': addr_node.get('addrtype')
            }
            if addr_node.get('vendor'): # For MAC addresses
                addr_info['vendor'] = addr_node.get('vendor')
            addresses.append(addr_info)
        if addresses:
            host_info['addresses'] = addresses
            primary_ip = next((a['address'] for a in addresses if a['type'] in ['ipv4', 'ipv6']), None)
            if primary_ip:
                 host_info['ip_address'] = primary_ip

        # --- Hostnames ---
        hostnames_node = host_node.find('hostnames')
        if hostnames_node is not None and hostnames_node.findall('hostname'):
            host_info['hostnames'] = []
            for hostname_entry in hostnames_node.findall('hostname'):
                host_info['hostnames'].append({
                    'name': hostname_entry.get('name'),
                    'type': hostname_entry.get('type')
                })
        
        # --- OS Detection ---
        os_node = host_node.find('os')
        if os_node is not None:
            host_info['os_detection'] = {}
            
            # OS Matches
            osmatch_nodes = os_node.findall('osmatch')
            if osmatch_nodes:
                host_info['os_detection']['osmatches'] = []
                for osmatch_node in osmatch_nodes: # Nmap can list multiple OS matches
                    osmatch_data = {
                        'name': osmatch_node.get('name'),
                        'accuracy': osmatch_node.get('accuracy')
                    }
                    osclasses = []
                    for osclass_node in osmatch_node.findall('osclass'):
                        osclasses.append({
                            'type': osclass_node.get('type'),
                            'vendor': osclass_node.get('vendor'),
                            'osfamily': osclass_node.get('osfamily'),
                            'osgen': osclass_node.get('osgen'),
                            'accuracy': osclass_node.get('accuracy'),
                            'cpe': [cpe.text for cpe in osclass_node.findall('cpe')]
                        })
                    if osclasses:
                        osmatch_data['osclasses'] = osclasses
                    host_info['os_detection']['osmatches'].append(osmatch_data)
            
            # Ports used for OS detection
            portused_nodes = os_node.findall('portused')
            if portused_nodes:
                host_info['os_detection']['ports_used_for_os_scan'] = []
                for pu_node in portused_nodes:
                    host_info['os_detection']['ports_used_for_os_scan'].append({
                        'state': pu_node.get('state'),
                        'proto': pu_node.get('proto'),
                        'portid': pu_node.get('portid')
                    })
            
            # OS Fingerprint (if available)
            osfingerprint_node = os_node.find('osfingerprint')
            if osfingerprint_node is not None and osfingerprint_node.get('fingerprint'):
                 host_info['os_detection']['fingerprint'] = osfingerprint_node.get('fingerprint')


        # --- Ports Information ---
        ports_info = []
        ports_node = host_node.find('ports')
        if ports_node is not None:
            for port_node in ports_node.findall('port'):
                port_details = {
                    'protocol': port_node.get('protocol'),
                    'portid': port_node.get('portid')
                }

                state_node = port_node.find('state')
                if state_node is not None:
                    port_details['state'] = state_node.get('state')
                    port_details['reason'] = state_node.get('reason')
                    if state_node.get('reason_ttl'):
                        port_details['reason_ttl'] = state_node.get('reason_ttl')


                service_node = port_node.find('service')
                if service_node is not None:
                    port_details['service'] = {
                        'name': service_node.get('name'),
                        'product': service_node.get('product'),
                        'version': service_node.get('version'),
                        'extrainfo': service_node.get('extrainfo'),
                        'method': service_node.get('method'),
                        'confidence': service_node.get('conf'), # 'conf' attribute for confidence
                        'ostype': service_node.get('ostype'),
                        'devicetype': service_node.get('devicetype'),
                        'hostname': service_node.get('hostname') # some services report hostname
                    }
                    # Remove None values from service dictionary for cleaner output
                    port_details['service'] = {k: v for k, v in port_details['service'].items() if v is not None}

                    cpe_nodes = service_node.findall('cpe')
                    if cpe_nodes:
                        port_details['service']['cpe'] = [cpe.text for cpe in cpe_nodes]
                
                # --- SCRIPT PARSING for each port ---
                port_scripts_data = []
                for script_node in port_node.findall('script'):
                    parsed_script = _parse_script_node(script_node)
                    if parsed_script: # Ensure something was parsed
                        port_scripts_data.append(parsed_script)

                if port_scripts_data:
                    port_details['scripts'] = port_scripts_data
                
                if port_details: # Ensure port_details is not empty
                    ports_info.append(port_details)

        if ports_info:
            host_info['ports'] = ports_info
        
        # --- Host Level Scripts ---
        hostscript_section_node = host_node.find('hostscript')
        if hostscript_section_node is not None:
            host_level_scripts_data = []
            for script_node in hostscript_section_node.findall('script'):
                parsed_script = _parse_script_node(script_node)
                if parsed_script:
                    host_level_scripts_data.append(parsed_script)
            if host_level_scripts_data:
                host_info['host_scripts'] = host_level_scripts_data

        # --- Other Host Information ---
        # Trace information
        trace_node = host_node.find('trace')
        if trace_node is not None:
            host_info['trace'] = {'port': trace_node.get('port'), 'proto': trace_node.get('proto'), 'hops': []}
            for hop_node in trace_node.findall('hop'):
                hop_data = {
                    'ttl': hop_node.get('ttl'),
                    'rtt': hop_node.get('rtt'),
                    'ipaddr': hop_node.get('ipaddr'),
                    'host': hop_node.get('host') # often the same as ipaddr if no PTR
                }
                host_info['trace']['hops'].append({k:v for k,v in hop_data.items() if v is not None})
        
        # Times
        times_node = host_node.find('times')
        if times_node is not None:
            host_info['times'] = {
                'srtt': times_node.get('srtt'), # Smoothed Round Trip Time
                'rttvar': times_node.get('rttvar'), # Round Trip Time Variance
                'to': times_node.get('to') # Timeout
            }
            host_info['times'] = {k:v for k,v in host_info['times'].items() if v is not None}

        if host_info: # Only add if we have gathered some information for the host
            hosts_data.append(host_info)

    scan_data['hosts'] = hosts_data
    return scan_data

def prep_database(db_path="nmap_results.db"):
    """
    Initializes the SQLite database with the required schema.
    Can be run before the Docker container starts to prevent lock issues.
    """
    print(f"[PREP] Initializing database schema in '{db_path}'...")
    conn = sqlite3.connect(db_path)
    conn.execute('PRAGMA journal_mode=WAL;')
    cursor = conn.cursor()
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time TEXT,
            command_line TEXT,
            import_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip_address TEXT,
            status TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            portid TEXT,
            protocol TEXT,
            state TEXT,
            service_name TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id)
        );
    ''')
    conn.commit()
    conn.close()
    print("[PREP] Database prepared successfully.")

def import_to_sqlite(parsed_data, db_path="nmap_results.db"):
    """
    Connects to SQLite, checks for duplicate scans, and inserts data if it's new.
    """
    if not parsed_data:
        return

    start_time = parsed_data.get('start_time')
    command_line = parsed_data.get('command_line')

    if not start_time or not command_line:
        print("Warning: 'start_time' or 'command_line' missing from XML. Cannot safely deduplicate.")
        print("Skipping import to prevent bad data.")
        return

    # Connect to Database with a timeout to prevent "database is locked" errors
    # timeout=15.0 tells SQLite to wait up to 15 seconds for locks to clear
    conn = sqlite3.connect(db_path, timeout=15.0)
    
    # Enable Write-Ahead Logging (WAL) for significantly better concurrency
    conn.execute('PRAGMA journal_mode=WAL;')
    
    cursor = conn.cursor()

    # 1. Initialize schema (Creates tables if they do not exist)
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time TEXT,
            command_line TEXT,
            import_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip_address TEXT,
            status TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            portid TEXT,
            protocol TEXT,
            state TEXT,
            service_name TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id)
        );
    ''')

    # 2. DEDUPLICATION CHECK
    # Search for start_time and command_line before proceeding
    cursor.execute(
        "SELECT id FROM scans WHERE start_time = ? AND command_line = ?", 
        (start_time, command_line)
    )
    existing_scan = cursor.fetchone()

    if existing_scan:
        print(f"[SKIP] Duplicate scan detected. (Start Time: {start_time}). Skipping import.")
        conn.close()
        return  # Safely exit the function

    # 3. INSERT STATEMENTS
    print(f"[IMPORT] New scan detected (Start Time: {start_time}). Inserting into database...")
    
    # Insert Scan
    cursor.execute(
        "INSERT INTO scans (start_time, command_line) VALUES (?, ?)", 
        (start_time, command_line)
    )
    scan_id = cursor.lastrowid # Get the newly generated scan ID

    # Insert Hosts and Ports
    for host in parsed_data.get('hosts', []):
        ip_address = host.get('ip_address', 'Unknown')
        status = host.get('status', {}).get('state', 'Unknown')
        
        cursor.execute(
            "INSERT INTO hosts (scan_id, ip_address, status) VALUES (?, ?, ?)", 
            (scan_id, ip_address, status)
        )
        host_id = cursor.lastrowid # Get the newly generated host ID

        for port in host.get('ports', []):
            portid = port.get('portid')
            protocol = port.get('protocol')
            state = port.get('state')
            service_name = port.get('service', {}).get('name', 'Unknown')
            
            cursor.execute(
                "INSERT INTO ports (host_id, portid, protocol, state, service_name) VALUES (?, ?, ?, ?, ?)", 
                (host_id, portid, protocol, state, service_name)
            )

    conn.commit()
    conn.close()
    print("[SUCCESS] Import complete.\n")


# --- Main execution example ---
if __name__ == "__main__":
    # 1. Check if the user provided enough arguments
    if len(sys.argv) < 2:
        print("Usage: python nmap-to-sqlite.py <nmap_output.xml>", file=sys.stderr)
        print("       python nmap-to-sqlite.py --prep", file=sys.stderr)
        sys.exit(1)

    # 2. Handle the database preparation flag
    if sys.argv[1] == '--prep':
        prep_database("nmap_results.db")
        sys.exit(0)

    # 3. Handle standard XML parsing and importing
    xml_file_to_parse = sys.argv[1]
    parsed_data = parse_nmap_xml(xml_file_to_parse)
    
    if parsed_data:
        # Run the SQLite Import and Deduplication logic
        db_filename = "nmap_results.db"
        import_to_sqlite(parsed_data, db_filename)
    else:
        print(f"No data parsed from '{xml_file_to_parse}'.", file=sys.stderr)
