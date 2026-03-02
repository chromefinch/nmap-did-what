import xml.etree.ElementTree as ET
import json
import sys
import sqlite3
import ipaddress # Used for integer-based IP sorting

def _parse_table_node(table_node):
    """Recursively parses a <table> node and its children (elem, table)."""
    table_content = {}
    direct_elements = {}
    unkeyed_direct_elements = []
    nested_tables_list = []

    for elem_node in table_node.findall('elem'):
        key = elem_node.get('key')
        value = elem_node.text
        if key: direct_elements[key] = value
        elif value: unkeyed_direct_elements.append(value)

    for sub_table_node in table_node.findall('table'):
        parsed_sub_table = _parse_table_node(sub_table_node)
        if parsed_sub_table: nested_tables_list.append(parsed_sub_table)

    table_key = table_node.get('key')

    if table_key:
        current_table_data_under_key = {}
        if direct_elements: current_table_data_under_key.update(direct_elements)
        if unkeyed_direct_elements:
            if current_table_data_under_key: current_table_data_under_key['_unkeyed_values'] = unkeyed_direct_elements
            else: current_table_data_under_key = {'_values': unkeyed_direct_elements}
        if nested_tables_list: current_table_data_under_key['tables'] = nested_tables_list
        table_content[table_key] = current_table_data_under_key
    else:
        if direct_elements: table_content.update(direct_elements)
        if unkeyed_direct_elements:
            if table_content: table_content['_unkeyed_values'] = unkeyed_direct_elements
            else: table_content['_values'] = unkeyed_direct_elements
        if nested_tables_list: table_content['tables'] = nested_tables_list
            
    return table_content

def _parse_script_node(script_node):
    """Helper to parse a <script> node."""
    script_info = {
        'id': script_node.get('id'),
        'output': script_node.get('output')
    }
    direct_elements = {}
    unkeyed_direct_elements = []
    
    for elem_node in script_node.findall('elem'):
        key = elem_node.get('key')
        value = elem_node.text
        if key: direct_elements[key] = value
        elif value: unkeyed_direct_elements.append(value)
            
    if direct_elements:
        script_info['elements'] = direct_elements
        if unkeyed_direct_elements: script_info['elements']['_unkeyed_values'] = unkeyed_direct_elements
    elif unkeyed_direct_elements: script_info['elements'] = {'_values': unkeyed_direct_elements}

    tables_data = []
    for table_node in script_node.findall('table'):
        parsed_table = _parse_table_node(table_node)
        if parsed_table: tables_data.append(parsed_table)
    if tables_data: script_info['tables'] = tables_data
        
    return script_info

def ip_to_int(ip_str):
    """Converts an IPv4 string to an integer for perfect SQL sorting."""
    try:
        return int(ipaddress.IPv4Address(ip_str))
    except:
        return 0 # Fallback for IPv6 or malformed strings

def parse_nmap_xml(xml_file):
    """Parses an Nmap XML file and extracts detailed host and service information."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML file '{xml_file}': {e}", file=sys.stderr)
        return None
    except FileNotFoundError:
        print(f"Error: File not found: '{xml_file}'", file=sys.stderr)
        return None

    scan_data = {
        'start_time': root.get('start'),
        'command_line': root.get('args'),
        'hosts': []
    }

    hosts_data = []

    for host_node in root.findall('host'):
        host_info = {}
        host_info['starttime'] = host_node.get('starttime')
        host_info['endtime'] = host_node.get('endtime')

        status_node = host_node.find('status')
        if status_node is not None:
            host_info['status'] = {
                'state': status_node.get('state'),
                'reason': status_node.get('reason'),
                'reason_ttl': status_node.get('reason_ttl')
            }

        addresses = []
        for addr_node in host_node.findall('address'):
            addr_info = {
                'address': addr_node.get('addr'),
                'type': addr_node.get('addrtype')
            }
            if addr_node.get('vendor'): addr_info['vendor'] = addr_node.get('vendor')
            addresses.append(addr_info)
        if addresses:
            host_info['addresses'] = addresses
            primary_ip = next((a['address'] for a in addresses if a['type'] in ['ipv4', 'ipv6']), None)
            if primary_ip:
                 host_info['ip_address'] = primary_ip

        hostnames_node = host_node.find('hostnames')
        if hostnames_node is not None and hostnames_node.findall('hostname'):
            host_info['hostnames'] = []
            for hostname_entry in hostnames_node.findall('hostname'):
                host_info['hostnames'].append({
                    'name': hostname_entry.get('name'),
                    'type': hostname_entry.get('type')
                })
        
        os_node = host_node.find('os')
        if os_node is not None:
            host_info['os_detection'] = {}
            osmatch_nodes = os_node.findall('osmatch')
            if osmatch_nodes:
                host_info['os_detection']['osmatches'] = []
                for osmatch_node in osmatch_nodes:
                    osmatch_data = {
                        'name': osmatch_node.get('name'),
                        'accuracy': osmatch_node.get('accuracy')
                    }
                    host_info['os_detection']['osmatches'].append(osmatch_data)
            
            osfingerprint_node = os_node.find('osfingerprint')
            if osfingerprint_node is not None and osfingerprint_node.get('fingerprint'):
                 host_info['os_detection']['fingerprint'] = osfingerprint_node.get('fingerprint')

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

                service_node = port_node.find('service')
                if service_node is not None:
                    port_details['service'] = {
                        'name': service_node.get('name'),
                        'product': service_node.get('product'),
                        'version': service_node.get('version'),
                        'extrainfo': service_node.get('extrainfo')
                    }
                    port_details['service'] = {k: v for k, v in port_details['service'].items() if v is not None}

                port_scripts_data = []
                for script_node in port_node.findall('script'):
                    parsed_script = _parse_script_node(script_node)
                    if parsed_script: port_scripts_data.append(parsed_script)

                if port_scripts_data: port_details['scripts'] = port_scripts_data
                if port_details: ports_info.append(port_details)

            host_info['ports_tested'] = 0
            host_info['ports_open'] = 0
            host_info['ports_closed'] = 0
            host_info['ports_filtered'] = 0
            
            for extra in ports_node.findall('extraports'):
                count = int(extra.get('count', 0))
                state = extra.get('state', '')
                if state == 'closed': host_info['ports_closed'] += count
                elif state == 'filtered': host_info['ports_filtered'] += count
                host_info['ports_tested'] += count

            for p in ports_info:
                st = p.get('state', '')
                if st == 'open': host_info['ports_open'] += 1
                elif st == 'closed': host_info['ports_closed'] += 1
                elif st == 'filtered': host_info['ports_filtered'] += 1
                host_info['ports_tested'] += 1

        if ports_info: host_info['ports'] = ports_info
        if host_info: hosts_data.append(host_info)

    runstats = root.find('runstats')
    if runstats is not None:
        finished = runstats.find('finished')
        if finished is not None: scan_data['elapsed_time'] = float(finished.get('elapsed', 0))
        hosts_stat = runstats.find('hosts')
        if hosts_stat is not None: scan_data['total_hosts'] = int(hosts_stat.get('up', 0))

    scan_data['hosts'] = hosts_data
    return scan_data

def init_database(db_path="nmap_results.db"):
    """Initializes the SQLite database with advanced schema, indexes, and FTS5."""
    conn = sqlite3.connect(db_path, timeout=15.0)
    conn.execute('PRAGMA journal_mode=WAL;')
    cursor = conn.cursor()
    
    # Core Tables
    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time INTEGER,
            elapsed_time REAL,
            total_open_ports INTEGER,
            total_hosts INTEGER,
            command_line TEXT,
            import_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT,
            ip_int INTEGER,
            hostname TEXT,
            os TEXT,
            start_time INTEGER,
            end_time INTEGER,
            ports_tested INTEGER,
            ports_open INTEGER,
            ports_closed INTEGER,
            ports_filtered INTEGER,
            status TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            port TEXT,
            protocol TEXT,
            state TEXT,
            state_change TEXT, 
            service_info TEXT,
            http_title TEXT,
            ssl_common_name TEXT,
            ssl_issuer TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id)
        );
        CREATE TABLE IF NOT EXISTS script_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port_id INTEGER,
            script_id TEXT,
            output TEXT,
            FOREIGN KEY(port_id) REFERENCES ports(id)
        );
    ''')
    
    # Performance Indexes
    cursor.executescript('''
        CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
        CREATE INDEX IF NOT EXISTS idx_hosts_ip_int ON hosts(ip_int);
        CREATE INDEX IF NOT EXISTS idx_hosts_times ON hosts(start_time, end_time);
        CREATE INDEX IF NOT EXISTS idx_ports_state ON ports(state);
        CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);
        CREATE INDEX IF NOT EXISTS idx_script_res_port ON script_results(port_id);
    ''')

    # FTS5 Virtual Table for blazing fast global search
    cursor.executescript('''
        CREATE VIRTUAL TABLE IF NOT EXISTS v_search USING fts5(
            host_id UNINDEXED, 
            content
        );
    ''')

    conn.commit()
    conn.close()

def import_to_sqlite(parsed_data, db_path="nmap_results.db"):
    """Connects to SQLite, checks for dupes, performs state tracking, and inserts."""
    if not parsed_data: return

    start_time = parsed_data.get('start_time')
    command_line = parsed_data.get('command_line')

    if not start_time or not command_line:
        print("Skipping import to prevent bad data.")
        return

    conn = sqlite3.connect(db_path, timeout=15.0)
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM scans WHERE start_time = ? AND command_line = ?", (start_time, command_line))
    if cursor.fetchone():
        print(f"[SKIP] Duplicate scan detected. (Start Time: {start_time}).")
        conn.close()
        return

    print(f"[IMPORT] Processing new scan into database...")
    try: scan_start_time = int(start_time)
    except: scan_start_time = 0
        
    cursor.execute(
        "INSERT INTO scans (start_time, elapsed_time, total_open_ports, total_hosts, command_line) VALUES (?, ?, ?, ?, ?)", 
        (scan_start_time, parsed_data.get('elapsed_time', 0), sum(h.get('ports_open', 0) for h in parsed_data.get('hosts', [])), parsed_data.get('total_hosts', 0), command_line)
    )
    scan_id = cursor.lastrowid

    for host in parsed_data.get('hosts', []):
        ip = host.get('ip_address', 'Unknown')
        ip_int = ip_to_int(ip)
        
        hostname = host.get('hostnames')[0].get('name', '') if host.get('hostnames') else ""
        os_name = host['os_detection']['osmatches'][0].get('name', 'Unknown') if host.get('os_detection') and host['os_detection'].get('osmatches') else "Unknown"
            
        try: h_start = int(host.get('starttime', 0)) * 1000
        except: h_start = scan_start_time * 1000
        try: h_end = int(host.get('endtime', 0)) * 1000
        except: h_end = h_start

        # --- STATE DELTA TRACKING ---
        # Look up the ports from the most recent scan for this specific IP address
        cursor.execute('''
            SELECT p.port, p.state
            FROM hosts h JOIN ports p ON h.id = p.host_id
            WHERE h.ip = ? AND h.scan_id = (
                SELECT MAX(scan_id) FROM hosts WHERE ip = ? AND scan_id < ?
            )
        ''', (ip, ip, scan_id))
        prev_ports = {row[0]: row[1] for row in cursor.fetchall()}
        
        cursor.execute(
            "INSERT INTO hosts (scan_id, ip, ip_int, hostname, os, start_time, end_time, ports_tested, ports_open, ports_closed, ports_filtered, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
            (scan_id, ip, ip_int, hostname, os_name, h_start, h_end, host.get('ports_tested', 0), host.get('ports_open', 0), host.get('ports_closed', 0), host.get('ports_filtered', 0), host.get('status', {}).get('state', 'Unknown'))
        )
        host_id = cursor.lastrowid

        for port in host.get('ports', []):
            portid = port.get('portid')
            protocol = port.get('protocol')
            state = port.get('state')
            
            # Compare current state to previous state
            state_change = 'new_host'
            if prev_ports:
                if portid in prev_ports:
                    state_change = 'unchanged' if prev_ports[portid] == state else f"{prev_ports[portid]} -> {state}"
                else:
                    state_change = 'newly_opened'
            
            srv = port.get('service', {})
            service_info = " ".join([p for p in [srv.get('name', ''), srv.get('product', ''), srv.get('version', '')] if p]).strip() or 'Unknown'

            http_title, ssl_common_name, ssl_issuer = "", "", ""
            fts_content_list = [ip, hostname, os_name, portid, service_info]
            
            # Handle Scripts & Normalize into new table
            scripts_to_insert = []
            for script in port.get('scripts', []):
                script_id = script.get('id', '')
                script_output_text = script.get('output', '')
                
                if script_id and script_output_text:
                    scripts_to_insert.append((script_id, script_output_text))
                    fts_content_list.append(script_output_text)
                    
                if script_id == 'http-title':
                    elements = script.get('elements', {})
                    http_title = elements['title'] if isinstance(elements, dict) and 'title' in elements else script_output_text
                elif script_id == 'ssl-cert':
                    tables = script.get('tables', [])
                    if isinstance(tables, list):
                        for t in tables:
                            if 'subject' in t and isinstance(t['subject'], dict): ssl_common_name = t['subject'].get('commonName', '')
                            if 'issuer' in t and isinstance(t['issuer'], dict): ssl_issuer = t['issuer'].get('commonName', '')
            
            fts_content_list.extend([http_title, ssl_common_name, ssl_issuer])

            cursor.execute(
                "INSERT INTO ports (host_id, port, protocol, state, state_change, service_info, http_title, ssl_common_name, ssl_issuer) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                (host_id, portid, protocol, state, state_change, service_info, http_title, ssl_common_name, ssl_issuer)
            )
            port_id = cursor.lastrowid
            
            # Insert individual script records
            for sid, out in scripts_to_insert:
                cursor.execute("INSERT INTO script_results (port_id, script_id, output) VALUES (?, ?, ?)", (port_id, sid, out))
            
            # Insert FTS5 Document for global searching
            fts_text = " ".join(filter(None, fts_content_list))
            cursor.execute("INSERT INTO v_search (host_id, content) VALUES (?, ?)", (host_id, fts_text))

    conn.commit()
    conn.close()
    print("[SUCCESS] Import complete.\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nmap-to-sqlite.py <nmap_output.xml>", file=sys.stderr)
        sys.exit(1)

    db_filename = "nmap_results.db"
    init_database(db_filename)
    
    xml_file_to_parse = sys.argv[1]
    parsed_data = parse_nmap_xml(xml_file_to_parse)
    
    if parsed_data: import_to_sqlite(parsed_data, db_filename)
    else: print(f"No data parsed from '{xml_file_to_parse}'.", file=sys.stderr)
