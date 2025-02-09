import re
import json
import ipaddress
import urllib.request
import os
import argparse
from datetime import datetime
from urllib.error import URLError, HTTPError
import hashlib

def generate_deterministic_device_id(name):
    """
    Generates a deterministic UUID based on a given name.
    :param name: String to be hashed (e.g., IP or Room Name)
    :return: UUIDv4-like string
    """
    hash_value = hashlib.sha256(name.encode()).hexdigest()
    return hash_value[:32]

def parse_dhcp_leases(file_paths, network_filters=None, active_only=False):
    """
    Parses one or multiple DHCP lease files and aggregates data.

    :param file_paths: List of paths to dhcpd.leases files.
    :param network_filters: List of networks in CIDR format to filter results.
    :return: Dictionary containing lease data.
    """
    leases_data = {"hosts_mac": {}, "hosts_ip": {}}
    errors = []
    
    for file_path in file_paths:
        if file_path.startswith("http://") or file_path.startswith("https://"):
            try:
                content = fetch_url_content(file_path)
                leases_data = merge_dhcp_data(leases_data, parse_lease_content(content, network_filters, active_only))
            except Exception as e:
                errors.append(dict(src=file_path, message=str(e)))
        elif os.path.exists(file_path):
            try:
                with open(file_path, "r") as file:
                    content = file.read()
                leases_data = merge_dhcp_data(leases_data, parse_lease_content(content, network_filters, active_only))
            except IOError as e:
                errors.append(dict(src=file_path, message=f"File error: {str(e)}"))
        else:
            errors.append(dict(src=file_path, message="Source is not a valid file or URL."))
    
    if errors:
        leases_data['errors'] = errors
    return leases_data


def fetch_url_content(url):
    """
    Fetches content from a URL with timeout and error handling.

    :param url: URL to fetch
    :return: Content of the URL
    """
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return response.read().decode('utf-8')
    except (URLError, HTTPError) as e:
        raise Exception(f"Error fetching URL {url}: {e}")
    except Exception as e:
        raise Exception(f"Unexpected error fetching URL {url}: {e}")


def is_host_active(ends):
    """
    Checks if a host is active based on the lease expiration time (ends).

    :param ends: Lease expiration date in 'YYYY/MM/DD HH:MM:SS' format
    :return: True if the host is active, False otherwise.
    """
    try:
        return datetime.now() < datetime.strptime(ends, "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return False  # If parsing fails, assume the host is inactive.


def parse_lease_content(content, network_filters=None, active_only=False):
    """
    Reads and parses the dhcpd.leases file, returning a structured dictionary.
    Can optionally filter by multiple networks in CIDR format.
    
    :param content: Content of the dhcpd.leases file
    :param network_filters: List of networks in CIDR format to filter results (optional)
    :return: Dictionary with data organized by IP and MAC
    """
    hosts_ip = {}
    hosts_mac = {}

    # Validate and convert network filters to ip_network objects
    networks = [ipaddress.ip_network(n, strict=False) for n in network_filters] if network_filters else []

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
        
        # Skip IPs that do not belong to any specified network
        if networks and not any(ipaddress.ip_address(ip) in net for net in networks):
            continue

        block = match.group(2)

        # Extract data within the block
        data = {key: regex.search(block) for key, regex in patterns.items()}
        data = {key: (match.group(1) if match else None) for key, match in data.items()}

        # Skip leases that are in "free" state
        if active_only and 'ends' in data and not is_host_active(data['ends']):
            continue  # Skip expired leases    
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

def address_info(file_paths, address):    
    try:
        content = parse_dhcp_leases(file_paths=file_paths, network_filters=[f'{address}/32'])['hosts_ip'][address]
        return {
            "ip": content['ip'],
            "mac": content['mac'],
            'device-id': generate_deterministic_device_id(content['mac']),
            'client-hostname': content['hostname']
        }
    except KeyError:
        return {
            "ip": address,
        }

def parse_lease_content_json(file_paths, network_filters=None, active_only=False, indent=3):
    """
    Reads multiple dhcpd.leases files and returns formatted JSON output.
    Can optionally filter by multiple networks in CIDR format.

    :param file_paths: List of paths to dhcpd.leases files
    :param network_filters: List of networks in CIDR format to filter results (optional)
    :param indent: JSON indentation level (default: 3)
    :return: Formatted JSON string
    """
    return json.dumps(parse_dhcp_leases(file_paths, network_filters, active_only), indent=indent)
  

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
    parser.add_argument("-n", "--network", action="append", required=False, help="Network address in CIDR format (e.g., 192.168.1.0/24)")
    parser.add_argument("--active-only", action="store_true", required=False, help="Return only active hosts")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    try:
        print(parse_lease_content_json(args.file, args.network, args.active_only))
    except Exception as e:
        print(json.dumps(dict(error=repr(e)), indent=3))
