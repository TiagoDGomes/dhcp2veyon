import re
import json
import ipaddress
import requests
import os
import argparse
from datetime import datetime


def parse_dhcp_leases(file_paths, network_filter=None):
    """
    Parses one or multiple DHCP lease files and aggregates data.

    :param file_paths: List of paths to dhcpd.leases files.
    :return: Dictionary containing lease data.
    """
    leases_data = {"hosts_mac": {}, "hosts_ip": {}}
    for file_path in file_paths:
        if file_path.startswith("http://") or file_path.startswith("https://"):         
            response = requests.get(file_path)
            response.raise_for_status()  # Raise error if request fails
            content = response.text
        elif os.path.exists(file_path):
            with open(file_path, "r") as file:
                content = file.read()        
        else:
            raise FileNotFoundError(f"Source '{file_path}' is not a valid file or URL.")
        leases_data = merge_dhcp_data(leases_data, parse_lease_content(content, network_filter))
    return leases_data

def parse_lease_content(content, network_filter=None):
    """
    Reads and parses the dhcpd.leases file, returning a structured dictionary.
    Can optionally filter by a specific network in CIDR format (e.g., "192.168.1.0/24").
    
    :param file_path: Path to the dhcpd.leases file
    :param network_filter: Network in CIDR format to filter results (optional)
    :return: Dictionary with data organized by IP and MAC
    """
    hosts_ip = {}
    hosts_mac = {}

    # Validate and convert network filter to an ip_network object
    network = ipaddress.ip_network(network_filter, strict=False) if network_filter else None

    # Regex to capture each "lease { ... }" block
    lease_pattern = re.compile(r'lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{(.*?)}', re.MULTILINE | re.DOTALL)

    # Individual regex patterns to extract data within the lease block
    patterns = {
        "mac": re.compile(r'hardware ethernet\s+([0-9a-f:]+);', re.IGNORECASE),
        "hostname": re.compile(r'client-hostname\s+"([^"]+)";', re.IGNORECASE),
        "bind_state": re.compile(r'binding state\s+(\w+);', re.IGNORECASE),
        "vendor": re.compile(r'set vendor-class-identifier\s*=\s*"([^"]+)";', re.IGNORECASE),
        "starts": re.compile(r'starts\s+\d+\s+([\d/]+ [\d:]+);', re.IGNORECASE),
        "cltt": re.compile(r'cltt\s+\d+\s+([\d/]+ [\d:]+);', re.IGNORECASE),
        "ends": re.compile(r'ends\s+\d+\s+([\d/]+ [\d:]+);', re.IGNORECASE)
    }

    matches = list(lease_pattern.finditer(content))

    for match in matches:
        ip = match.group(1)
        
        # Skip IPs that do not belong to the specified network
        if network and ipaddress.ip_address(ip) not in network:
            continue

        block = match.group(2)

        # Extract data within the block
        data = {key: regex.search(block) for key, regex in patterns.items()}
        data = {key: (match.group(1) if match else None) for key, match in data.items()}

        mac = data["mac"]
        if not data["hostname"]:
            data["hostname"] = f"host_{mac.replace(':', '')}" if mac else "unknown"

        lease_info = {"ip": ip, **data}

        # Store in the IP-based dictionary
        hosts_ip[ip] = lease_info

        # Store in the MAC-based dictionary
        mac_key = mac if mac else "unknown"
        hosts_mac.setdefault(mac_key, []).append(lease_info)

    # Sort results by IP (optional)
    hosts_ip = dict(sorted(hosts_ip.items(), key=lambda item: item[0]))

    return {"hosts_mac": hosts_mac, "hosts_ip": hosts_ip}

def parse_lease_content_json(file_paths, network_filter=None, indent=3):
    """
    Reads multiple dhcpd.leases files and returns formatted JSON output.
    Can optionally filter by a specific network in CIDR format.

    :param file_paths: List of paths to dhcpd.leases files
    :param network_filter: Network in CIDR format to filter results (optional)
    :param indent: JSON indentation level (default: 3)
    :return: Formatted JSON string
    """
    return json.dumps(parse_dhcp_leases(file_paths, network_filter), indent=indent)

def merge_dhcp_data(existing_data, new_data):
    """
    Merges new DHCP lease data into an existing dataset, prioritizing active leases.

    :param existing_data: Current aggregated lease data.
    :param new_data: New lease data to be merged.
    :return: Merged lease dataset.
    """
    for ip, new_lease in new_data["hosts_ip"].items():
        if ip not in existing_data["hosts_ip"] or is_newer_lease(existing_data["hosts_ip"][ip], new_lease):
            existing_data["hosts_ip"][ip] = new_lease
    existing_data['hosts_mac'] = existing_data['hosts_mac'] | new_data['hosts_mac']
    return existing_data

def is_newer_lease(existing_lease, new_lease):
    """
    Determines if the new lease is more recent than the existing lease.

    :param existing_lease: Existing lease data.
    :param new_lease: New lease data.
    :return: True if the new lease is newer, False otherwise.
    """
    try:
        existing_time = datetime.strptime(existing_lease["ends"], "%Y/%m/%d %H:%M:%S")
        new_time = datetime.strptime(new_lease["ends"], "%Y/%m/%d %H:%M:%S")
        return new_time > existing_time
    except ValueError:
        return False  # If parsing fails, assume the existing lease is newer

def parse_arguments():
    """
    Parses command-line arguments for the script.
    """
    parser = argparse.ArgumentParser(description="Convert DHCP leases to JSON.")
    parser.add_argument("-f", "--file", action="append", required=True, help="Path to the dhcpd.leases file or URL")
    parser.add_argument("-n", "--network", required=False, help="Network address in CIDR format (e.g., 192.168.1.0/24)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    try:
        print(parse_lease_content_json(args.file, args.network))
    except ValueError as e:
        print(f"Error: {e}")
