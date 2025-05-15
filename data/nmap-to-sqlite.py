import xml.etree.ElementTree as ET
import json
import sys # For accessing command-line arguments

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
        return []
    except FileNotFoundError:
        print(f"Error: File not found: '{xml_file}'", file=sys.stderr)
        return []

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
        # Nmap typically provides one primary address type used for the scan (e.g. ipv4)
        # and might list others if available (e.g. MAC if on local network)
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
            # For convenience, add top-level ip_address if an IPv4 or IPv6 is primary
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

    return hosts_data

# --- Main execution example ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nmap_parser.py <nmap_output.xml>", file=sys.stderr)
        # Create a dummy XML file for testing if no argument is provided
        print("No XML file provided. Creating and using 'dummy_nmap_output.xml' for demonstration.", file=sys.stderr)
        dummy_xml_content = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -A -sV -T4 scanme.nmap.org example.com" start="1684190400" startstr="Wed May 15 16:00:00 2024" version="7.92" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1024"/>
  <verbose level="0"/>
  <debugging level="0"/>
  <host starttime="1684190401" endtime="1684190405">
    <status state="up" reason="syn-ack" reason_ttl="0"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <hostnames>
      <hostname name="scanme.nmap.org" type="user"/>
      <hostname name="scanme.nmap.org" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10">
          <cpe>cpe:/a:openssh:openssh:8.2p1</cpe>
          <cpe>cpe:/o:linux:linux_kernel</cpe>
        </service>
        <script id="ssh-hostkey" output="RSA key fingerprint is SHA256:KEYDATA...">
          <elem key="type">ssh-rsa</elem>
          <elem key="key">AAAAB3NzaC1yc2EAAAADAQABAAABAQ...</elem>
          <elem key="bits">2048</elem>
          <elem key="fingerprint">abcdef1234567890</elem>
        </script>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10">
          <cpe>cpe:/a:apache:http_server:2.4.41</cpe>
        </service>
        <script id="http-title" output="Go ahead and ScanMe!"><elem key="title">Go ahead and ScanMe!</elem></script>
        <script id="http-server-header" output="Apache/2.4.41 (Ubuntu)"><elem>Apache/2.4.41 (Ubuntu)</elem></script>
        <script id="http-methods" output="GET HEAD POST OPTIONS">
            <table> <elem key="GET">1</elem>
                <elem key="HEAD">1</elem>
                <elem key="POST">1</elem>
                <elem key="OPTIONS">1</elem>
            </table>
            <table key="potentially_dangerous_methods"> <elem key="TRACE">1</elem>
            </table>
        </script>
        <script id="http-ntlm-info" output="target_name: SCANME_WEB&#xa;netbios_domain_name: WORKGROUP">
          <elem key="TargetName">SCANME_WEB</elem>
          <elem key="NetBIOSDomainName">WORKGROUP</elem>
          <elem key="NetBIOSComputerName">SCANME_WEB_NB</elem>
          <elem key="DNSDomainName">scanme.nmap.org</elem>
          <elem key="DNSComputerName">scanme.nmap.org</elem>
          <elem key="ProductVersion">6.0</elem>
        </script>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="https" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" tunnel="ssl" method="probed" conf="10">
            <cpe>cpe:/a:apache:http_server:2.4.41</cpe>
        </service>
        <script id="ssl-cert" output="Subject: commonName=scanme.nmap.org">
            <table key="subject">
                <elem key="commonName">scanme.nmap.org</elem>
            </table>
            <table key="issuer">
                <elem key="organizationalUnitName">Let's Encrypt</elem>
                <elem key="commonName">R3</elem>
            </table>
            <elem key="pem">-BEGIN CERTIFICATE-...</elem>
        </script>
        <script id="ssl-enum-ciphers" output="...">
            <table key="TLSv1.2">
                <table key="ciphers">
                    <elem key="name">TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256</elem>
                    <elem key="strength">A</elem>
                </table>
                <elem key="compressors">NULL</elem>
                <table key="server_preference">
                     <elem key="order">server</elem>
                </table>
            </table>
        </script>
      </port>
      <port protocol="tcp" portid="3389"> <state state="filtered" reason="no-response" reason_ttl="0"/>
        <service name="ms-wbt-server" method="table" conf="3"/>
        <script id="rdp-ntlm-info" output="NTLMSSP (Windows Server 2019 Standard 17763)">
            <elem key="Target_Name">RDS-SERVER</elem>
            <elem key="NetBIOS_Domain_Name">CORP</elem>
            <elem key="NetBIOS_Computer_Name">RDS-SERVER</elem>
            <elem key="DNS_Domain_Name">corp.example.com</elem>
            <elem key="DNS_Computer_Name">rds-server.corp.example.com</elem>
            <elem key="Product_Version">10.0.17763</elem>
        </script>
      </port>
    </ports>
    <os>
      <portused state="open" proto="tcp" portid="22"/>
      <osmatch name="Linux 5.X" accuracy="100"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="100"/></osmatch>
    </os>
    <hostscript>
        <script id="smb-os-discovery" output="Windows Server 2019 Standard 17763">
            <elem key="os">Windows Server 2019 Standard 17763</elem>
            <elem key="lanmanager_dialect">SMB 2.02/2.10</elem>
            <elem key="server_nt_status">0x00000000</elem>
        </script>
    </hostscript>
    <trace port="80" proto="tcp">
      <hop ttl="1" rtt="1.23" ipaddr="192.168.0.1" host="router.example.com"/>
    </trace>
    <times srtt="12345" rttvar="6789" to="100000"/>
  </host>
  <runstats>
    <finished time="1684190410" timestr="Wed May 15 16:00:10 2024" elapsed="10" summary="Nmap done; 1 IP address (1 host up) scanned in 10.00 seconds" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""
        xml_file_to_parse = "dummy_nmap_output.xml"
        with open(xml_file_to_parse, "w", encoding="utf-8") as f:
            f.write(dummy_xml_content)
    else:
        xml_file_to_parse = sys.argv[1]

    parsed_data = parse_nmap_xml(xml_file_to_parse)
    if parsed_data:
        print(json.dumps(parsed_data, indent=2))
    else:
        print(f"No data parsed from '{xml_file_to_parse}'.", file=sys.stderr)

    # Example of how to access specific script data after parsing:
    # for host in parsed_data:
    #     if 'ip_address' in host: # Check if ip_address key exists
    #         print(f"\nHost: {host.get('ip_address')}")
    #         if 'ports' in host:
    #             for port in host['ports']:
    #                 if 'scripts' in port:
    #                     for script in port['scripts']:
    #                         if script['id'] == 'http-ntlm-info' and 'elements' in script:
    #                             print(f"  Port {port.get('portid')}: NTLM Info: {script['elements']}")
    #                         if script['id'] == 'rdp-ntlm-info' and 'elements' in script:
    #                             print(f"  Port {port.get('portid')}: RDP NTLM Info: {script['elements']}")
    #                         if script['id'] == 'ssl-cert' and 'tables' in script:
    #                             for table_entry in script['tables']:
    #                                 if 'subject' in table_entry:
    #                                     print(f"  Port {port.get('portid')}: SSL Cert Subject: {table_entry['subject']}")
    #         if 'host_scripts' in host:
    #             for script in host['host_scripts']:
    #                 if 'elements' in script:
    #                      print(f"  Host Script '{script['id']}': {script['elements']}")

