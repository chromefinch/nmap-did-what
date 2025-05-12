#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET
import glob
import os
import sys
import argparse # For command-line arguments
from time import gmtime, strftime # For potential timestamp updates
import subprocess # To run external commands like xsltproc
import shutil # To check if xsltproc exists

# --- Configuration ---
# Default output filename if not specified via command-line
DEFAULT_OUTPUT_FILE = "combined_nmap_output.xml"

# XML Prolog (Header)
XML_PROLOG = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>
"""

# --- Functions ---

def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Combine multiple Nmap XML output files into one, optionally generating HTML.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Example Usage:
  Combine all detailed scans and generate default HTML:
    %(prog)s "detailed_scan_*.xml"

  Combine specific files, specifying XML output, and generate HTML:
    %(prog)s host1_scan.xml "network_192_*.xml" -o final_report.xml

  Combine files but skip HTML generation:
    %(prog)s *.xml --no-html
"""
    )
    parser.add_argument(
        'input_patterns',
        metavar='PATTERN_OR_FILE',
        nargs='+', # Require at least one pattern/file
        help='One or more Nmap XML filenames or glob patterns (e.g., "scan_*.xml", file1.xml).'
    )
    parser.add_argument(
        '-o', '--output',
        metavar='OUTPUT_XML_FILE', # Clarified this is XML output
        default=DEFAULT_OUTPUT_FILE,
        help=f'Filename for the combined XML output (default: {DEFAULT_OUTPUT_FILE}).'
    )
    parser.add_argument(
        '--no-html',
        action='store_true', # Makes it a boolean flag
        help='Skip the automatic generation of an HTML report using xsltproc.'
    )
    return parser.parse_args()

def find_xml_files(patterns):
    """Finds unique XML files matching the given patterns."""
    all_found_files = set()
    for pattern in patterns:
        found = glob.glob(pattern)
        if not found:
            print(f"Warning: No files found matching pattern '{pattern}'", file=sys.stderr)
        all_found_files.update(found) # Add files, automatically handles duplicates

    # Convert set to a sorted list for consistent processing order
    sorted_files = sorted(list(all_found_files))
    return sorted_files

def combine_nmap_xml(xml_files):
    """Parses and combines host data from multiple Nmap XML files."""
    if not xml_files:
        print("Error: No input XML files to process.", file=sys.stderr)
        return None # Indicate failure

    print(f"Combining data from {len(xml_files)} file(s)...")

    # Create a new nmaprun root element
    combined_root = ET.Element("nmaprun")

    # --- Attempt to copy attributes and set initial values from the first file ---
    first_file = xml_files[0]
    try:
        print(f"Using '{first_file}' for initial attributes and start time.")
        first_tree = ET.parse(first_file)
        first_root = first_tree.getroot()
        combined_root.attrib = first_root.attrib # Copy all attributes

        # Sensible overrides/updates for the combined file
        combined_root.set("start", str(int(os.path.getmtime(first_file)))) # Use first file's mtime as approx start
        combined_root.set("startstr", strftime("%Y-%m-%d %H:%M:%S %Z", gmtime(os.path.getmtime(first_file))))
        # Keep original scanner version if present, otherwise set default
        combined_root.set("scanner", first_root.get("scanner", "nmap"))
        # Update args to reflect combination
        original_args = first_root.get("args", "N/A")
        combined_root.set("args", f"Combined from multiple scans; first scan args: {original_args}")
        # Ensure version is present
        combined_root.set("version", first_root.get("version", "N/A"))


    except ET.ParseError as e:
        print(f"Error: Could not parse the first file '{first_file}' to get base attributes: {e}", file=sys.stderr)
        print("Warning: Combined file may lack some root attributes.", file=sys.stderr)
        # Set minimal required attributes if parsing fails
        combined_root.set("scanner", "nmap")
        combined_root.set("args", "Combined from multiple scans - base attributes unavailable")
        combined_root.set("start", str(int(os.path.getmtime(first_file)))) # Still use timestamp
        combined_root.set("startstr", strftime("%Y-%m-%d %H:%M:%S %Z", gmtime(os.path.getmtime(first_file))))
        combined_root.set("version", "N/A") # Unknown version
    except FileNotFoundError:
         print(f"Error: The first file '{first_file}' was not found during attribute processing.", file=sys.stderr)
         return None # Critical error
    except Exception as e:
         print(f"Error: Unexpected error processing first file '{first_file}': {e}", file=sys.stderr)
         return None # Critical error


    # --- Add all host elements from each XML file ---
    total_hosts_added = 0
    processed_files = 0
    skipped_files = 0
    latest_finish_time = 0 # Keep track of the latest finish time

    for xml_file in xml_files:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            hosts_in_file = 0
            for host in root.findall("host"):
                combined_root.append(host)
                hosts_in_file += 1
            total_hosts_added += hosts_in_file
            processed_files += 1
            print(f"  - Added {hosts_in_file} host(s) from '{xml_file}'")

            # Try to get finish time from runstats for accurate end time
            try:
                finish_time_str = root.find("./runstats/finished").get("time")
                if finish_time_str:
                    latest_finish_time = max(latest_finish_time, int(finish_time_str))
            except (AttributeError, TypeError, ValueError):
                 # Handle cases where runstats/finished/time is missing or invalid
                 # Fallback to file modification time if needed
                 latest_finish_time = max(latest_finish_time, int(os.path.getmtime(xml_file)))

        except ET.ParseError as e:
            print(f"Warning: Skipping file '{xml_file}' due to parsing error: {e}", file=sys.stderr)
            skipped_files += 1
        except FileNotFoundError:
             print(f"Warning: Skipping file '{xml_file}' as it was not found.", file=sys.stderr)
             skipped_files += 1
        except Exception as e:
            print(f"Warning: Skipping file '{xml_file}' due to unexpected error: {e}", file=sys.stderr)
            skipped_files += 1

    if processed_files == 0:
        print("Error: No files could be successfully processed.", file=sys.stderr)
        return None

    print(f"Total hosts added: {total_hosts_added}")
    if skipped_files > 0:
        print(f"Files skipped due to errors: {skipped_files}", file=sys.stderr)

    # --- Add/Update runstats ---
    # Remove existing runstats if copied from first file, then add a new summary
    existing_runstats = combined_root.find("runstats")
    if existing_runstats is not None:
        combined_root.remove(existing_runstats)

    runstats = ET.SubElement(combined_root, "runstats")
    finished = ET.SubElement(runstats, "finished")

    # Use the latest finish time found, or fallback to last file's mtime
    final_finish_time = latest_finish_time if latest_finish_time > 0 else int(os.path.getmtime(xml_files[-1]))
    final_finish_time_str = strftime("%Y-%m-%d %H:%M:%S %Z", gmtime(final_finish_time))

    finished.set("time", str(final_finish_time))
    finished.set("timestr", final_finish_time_str)
    finished.set("summary", f"Combined Nmap results; {total_hosts_added} host(s) total.")
    finished.set("elapsed", "N/A") # Elapsed time is hard to calculate accurately
    finished.set("exit", "success") # Assume success if we got this far

    hosts_stats = ET.SubElement(runstats, "hosts")
    # Note: Accurately summing up/down hosts requires parsing status in each file's host tag.
    # This provides a basic count based on appended host elements.
    hosts_stats.set("up", str(total_hosts_added))
    hosts_stats.set("down", "0") # Cannot determine from combined data easily
    hosts_stats.set("total", str(total_hosts_added))

    return combined_root

def write_combined_xml(output_file, root_element, prolog):
    """Writes the combined XML tree to the output file with the specified prolog."""
    combined_tree = ET.ElementTree(root_element)
    try:
        with open(output_file, "wb") as f:
            # Write the custom prolog/header first, encoded in UTF-8
            f.write(prolog.encode('utf-8'))
            # Write the XML tree, ensuring UTF-8 encoding, but NO automatic xml declaration
            combined_tree.write(f, encoding="utf-8", xml_declaration=False)
        return True # Indicate success
    except IOError as e:
        print(f"Error writing XML to '{output_file}': {e}", file=sys.stderr)
        return False # Indicate failure
    except Exception as e:
        print(f"An unexpected error occurred during XML writing: {e}", file=sys.stderr)
        return False # Indicate failure

def generate_html_report(xml_filepath):
    """Generates an HTML report from the Nmap XML file using xsltproc."""
    xsltproc_path = shutil.which("xsltproc")
    if not xsltproc_path:
        print("\nWarning: 'xsltproc' command not found in PATH.", file=sys.stderr)
        print("HTML report generation skipped. To enable, install xsltproc.", file=sys.stderr)
        print("(e.g., 'sudo apt install xsltproc' or 'sudo yum install libxslt')", file=sys.stderr)
        return False

    # Generate HTML filename based on XML filename
    html_filepath = os.path.splitext(xml_filepath)[0] + ".html"
    command = [xsltproc_path, xml_filepath, "-o", html_filepath]

    print(f"\nAttempting to generate HTML report: '{html_filepath}'...")
    print(f"Running command: {' '.join(command)}") # Show the command being run

    try:
        # Run xsltproc, capture output, check for errors
        result = subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8')
        print("HTML report generated successfully.")
        if result.stderr: # Print any warnings from xsltproc
             print("xsltproc stderr output:\n---", file=sys.stderr)
             print(result.stderr, file=sys.stderr)
             print("---", file=sys.stderr)
        return True
    except FileNotFoundError:
        # This case should be caught by shutil.which, but handle defensively
        print(f"Error: xsltproc not found at '{xsltproc_path}'.", file=sys.stderr)
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error: xsltproc failed with exit code {e.returncode}.", file=sys.stderr)
        print("Command output (stdout):\n---", file=sys.stderr)
        print(e.stdout, file=sys.stderr)
        print("---\nCommand output (stderr):\n---", file=sys.stderr)
        print(e.stderr, file=sys.stderr)
        print("---", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred while running xsltproc: {e}", file=sys.stderr)
        return False


# --- Main Execution ---
def main():
    """Main function to orchestrate the process."""
    args = parse_arguments()

    xml_files = find_xml_files(args.input_patterns)
    if not xml_files:
        print("Error: No input XML files found matching the specified pattern(s). Exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(xml_files)} XML file(s) to potentially combine:")
    # Optionally list files - can be long, keep commented unless needed for debugging
    # for f in xml_files:
    #     print(f"  - {f}")

    combined_root = combine_nmap_xml(xml_files)

    if combined_root is None:
        print("\nError: Failed to create combined XML structure. Exiting.", file=sys.stderr)
        sys.exit(1)

    # --- Write the Combined XML File ---
    xml_output_file = args.output
    if not write_combined_xml(xml_output_file, combined_root, XML_PROLOG):
        print("\nError: Failed to write combined XML file. Exiting.", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\nSuccessfully combined XML written to '{xml_output_file}'")

    # --- Generate HTML Report (if not skipped) ---
    if not args.no_html:
        if not generate_html_report(xml_output_file):
            # HTML generation failed or was skipped due to missing xsltproc
            # Decide if this should be a fatal error (sys.exit(1)) or just a warning.
            # Let's treat it as non-fatal for now.
            print("\nWarning: HTML report generation step failed or was skipped.", file=sys.stderr)
    else:
        print("\nSkipping HTML report generation as requested.")


if __name__ == "__main__":
    main()
