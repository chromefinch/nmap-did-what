#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET
import glob
import os
import sys
import argparse
import html
import collections
import re # For summary injection
from datetime import datetime

# --- Embedded CSS for the HTML Report ---
HTML_CSS = """
<style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; line-height: 1.6; }
    .container {
        width: 95%; /* Use more of the viewport width */
        max-width: 1600px; /* Increased max-width for wider screens */
        margin: 20px auto;
        background-color: #fff;
        padding: 20px;
        box-shadow: 0 0 15px rgba(0,0,0,0.1);
        border-radius: 8px;
    }
    h1, h2, h3, h4 { color: #2c3e50; margin-top: 1.5em; margin-bottom: 0.5em; }
    h1 { text-align: center; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 1em; font-size: 2.2em; }
    h2 { border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; font-size: 1.8em; }
    h3 { font-size: 1.4em; color: #34495e; }
    h4 { font-size: 1.1em; color: #7f8c8d; margin-top: 1.5em;} /* Added margin-top for spacing before tables */
    table { width: 100%; border-collapse: collapse; /* margin-bottom: 20px; <- Moved to wrapper */ font-size: 0.9em; }
    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; }
    th { background-color: #3498db; color: white; font-weight: bold; white-space: nowrap; /* Prevent th from wrapping */ }
    tr:nth-child(even) { background-color: #f9f9f9; }
    .summary-box { background-color: #ecf0f1; border-left: 5px solid #3498db; padding: 15px; margin-bottom: 25px; border-radius: 4px; }
    .summary-box ul { padding-left: 20px; }
    .summary-box ul ul { margin-top: 5px; margin-bottom: 10px;}
    .host-section { margin-bottom: 30px; padding: 20px; border: 1px solid #bdc3c7; border-radius: 5px; background-color: #fff; }
    .host-title { background-color: #2c3e50; color: white; padding: 10px; margin: -20px -20px 15px -20px; border-radius: 5px 5px 0 0; font-size: 1.6em;}
    .port-scripts pre, .host-scripts pre {
        background-color: #2d2d2d; color: #00ff00; /* Terminal-like */
        padding: 10px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word;
        font-family: 'Courier New', Courier, monospace; font-size: 0.85em; margin-top: 5px;
        max-height: 300px; /* Prevent extremely long script outputs from dominating page */
        overflow-y: auto; /* Allow vertical scroll for long script outputs */
    }
    .footer { text-align: center; margin-top: 30px; padding: 15px; font-size: 0.9em; color: #777; border-top: 1px solid #eee; }
    ul { list-style-type: square; padding-left: 20px; }
    li { margin-bottom: 5px; }
    .tag { display: inline-block; background-color: #e0e0e0; color: #555; padding: 2px 6px;
           border-radius: 3px; font-size: 0.8em; margin-right: 5px; margin-bottom: 3px; white-space: nowrap;}
    .tag-os { background-color: #27ae60; color: white; }
    .tag-service { background-color: #f39c12; color: white; }
    .tag-port-open { background-color: #2ecc71; color: white; }
    .tag-vuln { background-color: #e74c3c; color: white; }

    /* New styles for responsive table wrappers */
    .table-responsive-wrapper {
        overflow-x: auto;      /* Enables horizontal scrolling if content overflows */
        margin-bottom: 20px;   /* Restores bottom margin previously on the table */
        -webkit-overflow-scrolling: touch; /* Smoother scrolling on iOS */
    }
    .table-responsive-wrapper > table {
        margin-bottom: 0; /* Table inside wrapper doesn't need its own bottom margin */
        min-width: 600px; /* Suggest a minimum width for tables so they don't get too squished */
    }
    .port-table { /* Specifically for the ports table which can be very wide */
        min-width: 800px; /* Give it a larger min-width */
    }
</style>
"""

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Combine multiple Nmap XML files and generate a custom HTML report.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        'input_patterns',
        metavar='PATTERN_OR_FILE',
        nargs='+',
        help='One or more Nmap XML filenames or glob patterns (e.g., "scan_*.xml", file1.xml).'
    )
    parser.add_argument(
        '-o', '--output',
        metavar='OUTPUT_HTML_FILE',
        default="nmap_report.html",
        help='Filename for the generated HTML report (default: nmap_report.html).'
    )
    return parser.parse_args()

def find_xml_files(patterns):
    all_found_files = set()
    for pattern in patterns:
        found = glob.glob(pattern)
        if not found:
            print(f"Warning: No files found matching pattern '{pattern}'", file=sys.stderr)
        all_found_files.update(found)
    return sorted(list(all_found_files))

def parse_nmap_xml_files(xml_files):
    """
    Parses multiple Nmap XML files and extracts structured host data.
    """
    hosts_data = []
    scan_metadata = {
        'nmap_versions': set(),
        'scan_args': [], 
        'start_times': [],
        'end_times': [],
        'total_hosts_in_xml': 0, 
        'processed_files': len(xml_files),
        'file_errors': 0
    }
    first_file_processed_for_metadata = False

    for xml_file in xml_files:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            if not first_file_processed_for_metadata:
                scan_metadata['scan_args'] = root.get("args", "N/A")
                first_file_processed_for_metadata = True

            scan_metadata['nmap_versions'].add(root.get("version", "N/A"))
            if root.get("start"):
                scan_metadata['start_times'].append(int(root.get("start")))
            
            runstats = root.find("runstats/finished")
            if runstats is not None and runstats.get("time"):
                scan_metadata['end_times'].append(int(runstats.get("time")))

            for host_node in root.findall("host"):
                scan_metadata['total_hosts_in_xml'] += 1
                if host_node.find("status") is None or host_node.find("status").get("state") != "up":
                    continue 

                host_info = {
                    'ip_address': None, 'ipv6_address': None, 'mac_address': None,
                    'ptr_hostnames': [], 'user_hostnames': [], 'vendor': None,
                    'status': 'up', 'os_matches': [], 'os_CPEs': [], 
                    'ports': [], 'host_scripts': [],
                    'scan_file': os.path.basename(xml_file),
                    'start_time': host_node.get("starttime"), 
                    'end_time': host_node.get("endtime"),
                }

                for addr_node in host_node.findall("address"):
                    addr_type = addr_node.get("addrtype")
                    address = addr_node.get("addr")
                    if addr_type == "ipv4":
                        host_info['ip_address'] = address
                    elif addr_type == "ipv6":
                        host_info['ipv6_address'] = address
                    elif addr_type == "mac":
                        host_info['mac_address'] = address
                        host_info['vendor'] = addr_node.get("vendor")

                for hostname_node in host_node.findall("hostnames/hostname"):
                    hn_type = hostname_node.get("type")
                    hn_name = hostname_node.get("name")
                    if hn_type == "PTR":
                        host_info['ptr_hostnames'].append(hn_name)
                    elif hn_type == "user-set": 
                         host_info['user_hostnames'].append(hn_name)
                    elif hn_type == "user": 
                         host_info['user_hostnames'].append(hn_name)


                os_node = host_node.find("os")
                if os_node is not None:
                    for osmatch_node in os_node.findall("osmatch"):
                        match = {
                            'name': osmatch_node.get("name"),
                            'accuracy': osmatch_node.get("accuracy"),
                            'line': osmatch_node.get("line"),
                            'classes': []
                        }
                        for osclass_node in osmatch_node.findall("osclass"):
                            class_info = {
                                'type': osclass_node.get("type"),
                                'vendor': osclass_node.get("vendor"),
                                'osfamily': osclass_node.get("osfamily"),
                                'osgen': osclass_node.get("osgen"),
                                'accuracy': osclass_node.get("accuracy"),
                                'cpe': [c.text for c in osclass_node.findall("cpe")]
                            }
                            match['classes'].append(class_info)
                            host_info['os_CPEs'].extend(c.text for c in osclass_node.findall("cpe") if c.text) 
                        host_info['os_matches'].append(match)
                    host_info['os_matches'].sort(key=lambda x: int(x.get('accuracy', 0)), reverse=True)


                ports_node = host_node.find("ports")
                if ports_node is not None:
                    for port_node in ports_node.findall("port"):
                        state_node = port_node.find("state")
                        if state_node is None or state_node.get("state") != "open":
                            continue 

                        port_info = {
                            'portid': port_node.get("portid"),
                            'protocol': port_node.get("protocol"),
                            'state': state_node.get("state"),
                            'reason': state_node.get("reason"),
                            'service_name': None, # Initialized to None, updated below if service_node exists
                            'product': None, 
                            'version': None,
                            'extrainfo': None, 
                            'ostype': None, 
                            'method': None, 
                            'conf': None,
                            'cpe': [], 
                            'scripts': []
                        }
                        service_node = port_node.find("service")
                        if service_node is not None:
                            port_info.update({
                                'service_name': service_node.get("name") or "unknown", # Default to "unknown" if name attr is missing
                                'product': service_node.get("product"),
                                'version': service_node.get("version"),
                                'extrainfo': service_node.get("extrainfo"),
                                'ostype': service_node.get("ostype"),
                                'method': service_node.get("method"),
                                'conf': service_node.get("conf"),
                            })
                            port_info['cpe'] = [c.text for c in service_node.findall("cpe") if c.text]
                        else: # If no <service> tag, ensure service_name is not None for consistency
                            port_info['service_name'] = "unknown"


                        for script_node in port_node.findall("script"):
                            port_info['scripts'].append({
                                'id': script_node.get("id"),
                                'output': script_node.get("output")
                            })
                        host_info['ports'].append(port_info)

                hostscript_node = host_node.find("hostscript")
                if hostscript_node is not None:
                    for script_node in hostscript_node.findall("script"):
                        host_info['host_scripts'].append({
                            'id': script_node.get("id"),
                            'output': script_node.get("output")
                        })
                hosts_data.append(host_info)
        except ET.ParseError as e:
            print(f"Error parsing XML file {xml_file}: {e}", file=sys.stderr)
            scan_metadata['file_errors'] += 1
        except Exception as e:
            print(f"An unexpected error occurred with file {xml_file}: {e}", file=sys.stderr)
            scan_metadata['file_errors'] += 1
    
    unique_hosts_map = {}
    for host in hosts_data:
        key = host['ip_address'] or host['ipv6_address'] 
        if key:
            if key not in unique_hosts_map:
                unique_hosts_map[key] = host
            else:
                existing_host = unique_hosts_map[key]
                existing_host['ports'].extend(host['ports']) 
                existing_host['host_scripts'].extend(host['host_scripts'])
                if host['os_matches'] and \
                   (not existing_host['os_matches'] or \
                    (host['os_matches'][0].get('accuracy') and \
                     existing_host['os_matches'][0].get('accuracy') and \
                     int(host['os_matches'][0]['accuracy']) > int(existing_host['os_matches'][0]['accuracy']))):
                    existing_host['os_matches'] = host['os_matches']
                    existing_host['os_CPEs'] = host['os_CPEs']
    
    return list(unique_hosts_map.values()), scan_metadata


def generate_executive_summary_html(hosts_data, scan_metadata):
    if not hosts_data and scan_metadata.get('processed_files', 0) == scan_metadata.get('file_errors', 0) :
         return "<div class='summary-box'><p>No XML files could be processed or no 'up' hosts found.</p></div>"
    if not hosts_data:
        return "<div class='summary-box'><p>No 'up' hosts found in the processed XML files or no data to summarize.</p></div>"


    num_up_hosts = len(hosts_data)
    
    os_family_counter = collections.Counter()
    detailed_os_counter = collections.Counter()
    
    port_service_counter = collections.Counter()
    common_ports_counter = collections.Counter()
    tcp_open_ports = 0
    udp_open_ports = 0

    mac_vendor_counter = collections.Counter()
    
    product_counter = collections.Counter()
    product_version_details = collections.defaultdict(collections.Counter)
    
    os_cpe_counter = collections.Counter()
    app_cpe_counter = collections.Counter()
    
    script_id_counter = collections.Counter()
    vulnerable_script_hits = collections.defaultdict(lambda: {'count': 0, 'targets': set()})
    total_vulnerable_script_instances = 0

    for host in hosts_data:
        if host.get('vendor'):
            mac_vendor_counter[host['vendor']] += 1

        if host['os_matches']:
            best_os_match = host['os_matches'][0]
            if best_os_match.get('name'): 
                detailed_os_counter[best_os_match['name']] += 1
            
            primary_family = "Unknown"
            if best_os_match['classes']:
                for oc in best_os_match['classes']:
                    if oc.get('osfamily'):
                        primary_family = oc['osfamily']
                        break
            if primary_family == "Unknown" and best_os_match.get('name'): 
                name_lower = best_os_match['name'].lower()
                if "windows" in name_lower: primary_family = "Windows"
                elif "linux" in name_lower: primary_family = "Linux"
                elif "macos" in name_lower or "mac os x" in name_lower: primary_family = "Mac OS"
                elif "freebsd" in name_lower: primary_family = "FreeBSD"
                elif "solaris" in name_lower or "sunos" in name_lower: primary_family = "Solaris"
                elif "cisco" in name_lower: primary_family = "Cisco IOS" 
            os_family_counter[primary_family] += 1
            
            for os_cpe in host.get('os_CPEs', []):
                if os_cpe and os_cpe.startswith("cpe:/o"): 
                    os_cpe_counter[os_cpe] += 1
        else:
            os_family_counter["OS Not Detected"] += 1

        for port in host['ports']:
            port_proto_key = f"{port['portid']}/{port['protocol']}"
            common_ports_counter[port_proto_key] += 1
            if port['protocol'] == 'tcp':
                tcp_open_ports +=1
            elif port['protocol'] == 'udp':
                udp_open_ports +=1
            
            # Corrected logic for service_name_for_display:
            raw_service_name_value = port.get('service_name') 
            service_name_for_display = raw_service_name_value if raw_service_name_value is not None else "unknown"
            
            service_key = f"{port_proto_key} ({html.escape(service_name_for_display)})"
            port_service_counter[service_key] += 1

            product_name = port.get('product')
            if product_name:
                product_counter[product_name] += 1
                
                version_display_parts = []
                if port.get('version'):
                    version_display_parts.append(f"v{port['version']}")
                if port.get('extrainfo'):
                    version_display_parts.append(f"({port['extrainfo']})")
                
                full_version_display = " ".join(version_display_parts) if version_display_parts else "(Version N/A)"
                product_version_details[product_name][full_version_display] +=1
            
            for app_cpe in port.get('cpe', []):
                if app_cpe and app_cpe.startswith("cpe:/a"): 
                    app_cpe_counter[app_cpe] += 1
            
            target_id = f"{host.get('ip_address', host.get('ipv6_address', 'N/A'))}:{port['portid']}"
            for script in port.get('scripts', []):
                script_id = script.get('id', 'unknown_script')
                script_id_counter[script_id] += 1
                if "vuln" in script_id.lower() or "exploit" in script_id.lower() or "CVE-" in script_id.upper():
                    vulnerable_script_hits[script_id]['count'] += 1
                    vulnerable_script_hits[script_id]['targets'].add(target_id)
                    total_vulnerable_script_instances +=1
        
        host_target_id = f"{host.get('ip_address', host.get('ipv6_address', 'N/A'))} (host-level)"
        for script in host.get('host_scripts', []):
            script_id = script.get('id', 'unknown_script')
            script_id_counter[script_id] += 1
            if "vuln" in script_id.lower() or "exploit" in script_id.lower() or "CVE-" in script_id.upper():
                vulnerable_script_hits[script_id]['count'] += 1
                vulnerable_script_hits[script_id]['targets'].add(host_target_id)
                total_vulnerable_script_instances +=1

    summary_html = ["<div class='summary-box'>"]
    summary_html.append("<h3>Scan & Host Overview</h3><ul>")
    summary_html.append(f"<li>Files Processed: {scan_metadata['processed_files']} (Errors: {scan_metadata.get('file_errors',0)})</li>")
    if scan_metadata['start_times'] and scan_metadata['end_times']:
        overall_start = datetime.fromtimestamp(min(scan_metadata['start_times'])).strftime('%Y-%m-%d %H:%M:%S')
        overall_end = datetime.fromtimestamp(max(scan_metadata['end_times'])).strftime('%Y-%m-%d %H:%M:%S')
        summary_html.append(f"<li>Overall Scan Period (approx): {overall_start} to {overall_end}</li>")
    summary_html.append(f"<li>Nmap Versions Used: {html.escape(', '.join(sorted(list(scan_metadata['nmap_versions']))))}</li>")
    summary_html.append(f"<li>Representative Nmap Args: {html.escape(str(scan_metadata.get('scan_args', 'N/A')))}</li>")
    summary_html.append(f"<li>Total 'Up' Hosts Reported: {num_up_hosts}</li>")
    if mac_vendor_counter:
        summary_html.append(f"<li>Unique MAC Vendors Detected: {len(mac_vendor_counter)} (Top: {html.escape(mac_vendor_counter.most_common(1)[0][0]) if mac_vendor_counter else 'N/A'})</li>")
    summary_html.append("</ul>")

    summary_html.append("<h3>Operating Systems</h3><ul>")
    if os_family_counter:
        summary_html.append("<li><strong>OS Family Distribution:</strong><ul>")
        for os_name, count in os_family_counter.most_common():
            summary_html.append(f"<li><span class='tag tag-os'>{html.escape(os_name)}</span>: {count} host(s)</li>")
        summary_html.append("</ul></li>")
    if detailed_os_counter:
        summary_html.append("<li><strong>Detailed OS Detections (Top 5):</strong><ul>")
        for os_name, count in detailed_os_counter.most_common(5):
             summary_html.append(f"<li>{html.escape(os_name)}: {count} instance(s)</li>")
        summary_html.append("</ul></li>")
    if os_cpe_counter:
        summary_html.append("<li><strong>Common OS CPEs (Top 5):</strong><ul>")
        for cpe, count in os_cpe_counter.most_common(5):
            summary_html.append(f"<li>{html.escape(cpe)} ({count} instance(s))</li>")
        summary_html.append("</ul></li>")
    if not os_family_counter and not detailed_os_counter and not os_cpe_counter:
        summary_html.append("<li>No specific OS information detected or summarized.</li>")
    summary_html.append("</ul>")

    summary_html.append("<h3>Ports & Services</h3><ul>")
    summary_html.append(f"<li>Total Open TCP Ports Instances Logged: {tcp_open_ports}</li>") 
    summary_html.append(f"<li>Total Open UDP Ports Instances Logged: {udp_open_ports}</li>") 
    if common_ports_counter:
        summary_html.append("<li><strong>Most Common Open Ports (Top 10):</strong><ul>")
        for port_key, count in common_ports_counter.most_common(10): 
            summary_html.append(f"<li><span class='tag tag-port-open'>{html.escape(port_key)}</span>: {count} instance(s) across hosts</li>")
        summary_html.append("</ul></li>")
    if port_service_counter:
        summary_html.append("<li><strong>Most Common Services (Port & Name - Top 10):</strong><ul>")
        for service_key, count in port_service_counter.most_common(10):
            summary_html.append(f"<li><span class='tag tag-service'>{html.escape(service_key)}</span>: {count} instance(s)</li>")
        summary_html.append("</ul></li>")
    if not common_ports_counter and not port_service_counter:
         summary_html.append("<li>No open ports or services detected.</li>")
    summary_html.append("</ul>")

    summary_html.append("<h3>Software Products & Versions</h3><ul>")
    if product_counter:
        summary_html.append("<li><strong>Most Common Products (Top 5):</strong><ul>")
        for prod_name, count in product_counter.most_common(5):
            summary_html.append(f"<li><strong>{html.escape(prod_name)}</strong>: {count} instance(s) total")
            if prod_name in product_version_details:
                summary_html.append(" (Common versions:<ul>")
                for version_display, ver_count in product_version_details[prod_name].most_common(3):
                    summary_html.append(f"<li>{html.escape(version_display)}: {ver_count}</li>")
                summary_html.append("</ul>)</li>")
            else:
                summary_html.append("</li>")
        summary_html.append("</ul></li>")
    if app_cpe_counter:
        summary_html.append("<li><strong>Common Application CPEs (Top 5):</strong><ul>")
        for cpe, count in app_cpe_counter.most_common(5):
            summary_html.append(f"<li>{html.escape(cpe)} ({count} instance(s))</li>")
        summary_html.append("</ul></li>")
    if not product_counter and not app_cpe_counter:
        summary_html.append("<li>No specific software product information detected.</li>")
    summary_html.append("</ul>")
    
    if mac_vendor_counter:
        summary_html.append("<h3>Device Vendors (from MAC OUI)</h3><ul>")
        summary_html.append("<li><strong>Most Common MAC Vendors (Top 5):</strong><ul>")
        for vendor, count in mac_vendor_counter.most_common(5):
            summary_html.append(f"<li>{html.escape(vendor)}: {count} device(s)</li>")
        summary_html.append("</ul></li></ul>")

    summary_html.append("<h3>NSE Script Insights</h3><ul>")
    if script_id_counter:
        summary_html.append(f"<li>Total Unique NSE Script IDs Executed: {len(script_id_counter)}</li>")
        summary_html.append("<li><strong>Most Frequent Scripts (Top 5):</strong><ul>")
        for script_id, count in script_id_counter.most_common(5):
            summary_html.append(f"<li>{html.escape(script_id)}: {count} execution(s)</li>")
        summary_html.append("</ul></li>")
    
    if vulnerable_script_hits:
        summary_html.append(f"<li><strong>Potential Vulnerability/Exploit Script Hits:</strong> <span class='tag tag-vuln'>{total_vulnerable_script_instances}</span> instance(s) across <span class='tag tag-vuln'>{len(vulnerable_script_hits)}</span> unique script(s). (Review host details for specifics)</li>")
        summary_html.append("<li><strong>Top Vulnerability-Indicating Scripts (Top 3 by instances):</strong><ul>")
        sorted_vuln_scripts = sorted(vulnerable_script_hits.items(), key=lambda item: (item[1]['count'], len(item[1]['targets'])), reverse=True)
        for script_id, hits_data in sorted_vuln_scripts[:3]:
            summary_html.append(f"<li><span class='tag tag-vuln'>{html.escape(script_id)}</span>: {hits_data['count']} instance(s) on {len(hits_data['targets'])} target(s)/service(s)</li>")
        summary_html.append("</ul></li>")
    elif not script_id_counter: 
        summary_html.append("<li>No NSE scripts reported.</li>")
    else: 
        summary_html.append("<li>No scripts indicating potential vulnerabilities (e.g., containing 'vuln', 'exploit', 'CVE-') were identified by this summary.</li>")
    summary_html.append("</ul>")

    summary_html.append("</div>")
    return "\n".join(summary_html)


def generate_host_details_html(host_data):
    host_html = [f"<div class='host-section'>"]
    
    ip_display = html.escape(host_data.get('ip_address') or host_data.get('ipv6_address') or "N/A")
    host_title_parts = [f"Host: {ip_display}"]
    user_hostnames = host_data.get('user_hostnames', [])
    ptr_hostnames = host_data.get('ptr_hostnames', [])

    if user_hostnames:
        host_title_parts.append(f"({html.escape(', '.join(user_hostnames))})")
    elif ptr_hostnames: 
         host_title_parts.append(f"({html.escape(', '.join(ptr_hostnames))})")

    host_html.append(f"<h3 class='host-title'>{' '.join(host_title_parts)}</h3>")
    
    # Wrap Host Information table
    host_html.append("<h4>Host Information</h4><div class='table-responsive-wrapper'><table>")
    host_html.append(f"<tr><th>IPv4 Address</th><td>{html.escape(host_data.get('ip_address') or 'N/A')}</td></tr>")
    if host_data.get('ipv6_address'):
        host_html.append(f"<tr><th>IPv6 Address</th><td>{html.escape(host_data['ipv6_address'])}</td></tr>")
    if host_data.get('mac_address'):
        mac_info = html.escape(host_data['mac_address'])
        if host_data.get('vendor'):
            mac_info += f" (<span class='tag'>{html.escape(host_data['vendor'])}</span>)"
        host_html.append(f"<tr><th>MAC Address</th><td>{mac_info}</td></tr>")
    
    host_html.append(f"<tr><th>Status</th><td><span class='tag tag-port-open'>{html.escape(host_data.get('status', 'N/A'))}</span></td></tr>")
    if ptr_hostnames: 
        host_html.append(f"<tr><th>PTR Hostname(s)</th><td>{html.escape(', '.join(ptr_hostnames))}</td></tr>")
    if user_hostnames: 
        host_html.append(f"<tr><th>User-set Hostname(s)</th><td>{html.escape(', '.join(user_hostnames))}</td></tr>")
    host_html.append(f"<tr><th>Scanned In File</th><td>{html.escape(host_data.get('scan_file','N/A'))}</td></tr>")
    host_html.append("</table></div>") # Close Host Information table wrapper

    if host_data['os_matches']:
        # Wrap OS Detection table
        host_html.append("<h4>Operating System Detection (Top 3 Matches)</h4><div class='table-responsive-wrapper'><table>")
        host_html.append("<tr><th>OS Name Guess</th><th>Accuracy</th><th>OS Family (Best Class Guess)</th><th>OS CPEs (from classes)</th></tr>")
        for os_match in host_data['os_matches'][:3]: 
            name = html.escape(os_match.get('name', 'N/A'))
            accuracy = html.escape(os_match.get('accuracy', 'N/A')) + "%"
            family_display = "N/A"
            cpes_from_classes = set() 

            if os_match['classes']:
                sorted_classes = sorted(os_match['classes'], key=lambda x: int(x.get('accuracy', 0)), reverse=True)
                if sorted_classes and sorted_classes[0].get('osfamily'): 
                    family_display = f"<span class='tag tag-os'>{html.escape(sorted_classes[0]['osfamily'])}</span>"
                for osc in sorted_classes: 
                    cpes_from_classes.update(html.escape(c) for c in osc.get('cpe', []) if c)
            
            cpe_str = "<br>".join(f"<span class='tag'>{c}</span>" for c in sorted(list(cpes_from_classes))) if cpes_from_classes else "N/A"
            host_html.append(f"<tr><td>{name}</td><td>{accuracy}</td><td>{family_display}</td><td>{cpe_str}</td></tr>")
        host_html.append("</table></div>") # Close OS Detection table wrapper

    if host_data['ports']:
        # Wrap Open Ports table
        host_html.append("<h4>Open Ports</h4><div class='table-responsive-wrapper'><table class='port-table'>") # Added port-table class
        host_html.append("<tr><th>Port/Proto</th><th>Service</th><th>Product</th><th>Version</th><th>ExtraInfo</th><th>CPEs</th><th>Scripts</th></tr>")
        sorted_ports = sorted(host_data['ports'], key=lambda p: (int(p['portid']), p['protocol']))
        for port in sorted_ports:
            port_id_proto = f"<span class='tag tag-port-open'>{html.escape(port['portid'])}/{html.escape(port['protocol'])}</span>"
            service = html.escape(port.get('service_name', 'unknown')) 
            product = html.escape(port.get('product') or '')
            version = html.escape(port.get('version') or '')
            extrainfo = html.escape(port.get('extrainfo') or '')
            cpes = "<br>".join(f"<span class='tag'>{html.escape(c)}</span>" for c in port.get('cpe', []) if c) or "N/A"
            
            scripts_html = []
            for script in port.get('scripts', []):
                script_id = html.escape(script.get('id', 'N/A'))
                script_output = html.escape(script.get('output', 'N/A'))
                tag_class = "tag-vuln" if "vuln" in script_id.lower() or "exploit" in script_id.lower() or "cve-" in script_id.lower() else "tag"
                scripts_html.append(f"<strong><span class='{tag_class}'>{script_id}</span>:</strong><pre>{script_output}</pre>")
            scripts_str = "".join(scripts_html) if scripts_html else "N/A"

            host_html.append(f"<tr><td>{port_id_proto}</td><td>{service}</td><td>{product}</td><td>{version}</td><td>{extrainfo}</td><td>{cpes}</td><td>{scripts_str}</td></tr>")
        host_html.append("</table></div>") # Close Open Ports table wrapper

    if host_data['host_scripts']:
        host_html.append("<h4>Host-Level Scripts</h4><div class='host-scripts'>") # This is not a table, so direct wrapper might not be needed unless content gets extremely wide.
        for script in host_data['host_scripts']:
            script_id = html.escape(script.get('id', 'N/A'))
            script_output = html.escape(script.get('output', 'N/A'))
            tag_class = "tag-vuln" if "vuln" in script_id.lower() or "exploit" in script_id.lower() or "cve-" in script_id.lower() else "tag"
            host_html.append(f"<h5><span class='{tag_class}'>{script_id}</span></h5><pre>{script_output}</pre>")
        host_html.append("</div>")

    host_html.append("</div>") 
    return "\n".join(host_html)


def generate_html_report(hosts_data, scan_metadata, output_filename):
    print(f"Generating HTML report: {output_filename}...")
    
    hosts_data.sort(key=lambda h: (
        [int(x) for x in h['ip_address'].split('.')] if h.get('ip_address') and '.' in h['ip_address'] and h['ip_address'].count('.') == 3 and all(p.isdigit() for p in h['ip_address'].split('.')) else [0,0,0,0], 
        h.get('ipv6_address') or "" 
    ))

    report_title = "Combined Nmap Scan Report"
    generation_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')

    html_content = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        f"<meta charset='UTF-8'><title>{html.escape(report_title)}</title>",
        HTML_CSS,
        "</head>",
        "<body>",
        "<div class='container'>",
        f"<h1>{html.escape(report_title)}</h1>"
    ]

    html_content.append("<h2>Executive Summary</h2>")
    html_content.append(generate_executive_summary_html(hosts_data, scan_metadata))

    html_content.append("<h2>Detailed Host Information</h2>")
    if hosts_data:
        for host in hosts_data:
            html_content.append(generate_host_details_html(host))
    else:
        html_content.append("<p>No 'up' hosts with details to display.</p>")

    html_content.append(f"<div class='footer'>Report generated by Nmap HTML Reporter on {generation_time}</div>")
    html_content.append("</div></body></html>")

    try:
        with open(output_filename, "w", encoding="utf-8") as f:
            f.write("\n".join(html_content))
        print(f"HTML report successfully written to {output_filename}")
    except IOError as e:
        print(f"Error writing HTML report to {output_filename}: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    args = parse_arguments()
    xml_files = find_xml_files(args.input_patterns)

    if not xml_files:
        print("No XML files found matching the pattern(s). Exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(xml_files)} XML file(s) to process:")
    for f_path in xml_files:
        print(f"  - {f_path}")

    hosts_data, scan_metadata = parse_nmap_xml_files(xml_files)
    
    if not hosts_data and scan_metadata.get('processed_files', 0) > 0 and scan_metadata.get('processed_files') == scan_metadata.get('file_errors',0):
         print("\nAll XML files failed to parse. Cannot generate report.", file=sys.stderr)
         sys.exit(1)
    elif not hosts_data:
         print("\nNo 'up' host data extracted from the provided XML files. Report will be minimal or empty of host details.", file=sys.stdout)
    else:
        print(f"\nExtracted data for {len(hosts_data)} unique 'up' hosts.")

    generate_html_report(hosts_data, scan_metadata, args.output)

if __name__ == "__main__":
    main()
