import re
import json
import ipaddress

def parse_dhcp_leases(file_path, network_filter=None):
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

    with open(file_path) as f:
        content = f.read()

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

def parse_dhcp_leases_json(file_path, network_filter=None, indent=3):
    """
    Reads the dhcpd.leases file and returns formatted JSON output.
    Can optionally filter by a specific network in CIDR format.

    :param file_path: Path to the dhcpd.leases file
    :param network_filter: Network in CIDR format to filter results (optional)
    :param indent: JSON indentation level (default: 3)
    :return: Formatted JSON string
    """
    return json.dumps(parse_dhcp_leases(file_path, network_filter), indent=indent)

if __name__ == "__main__":
    import sys
    if len(sys.argv) not in [2, 3]:
        print("Usage: python dhcp_parser.py <path_to_dhcpd.leases> [network_filter]")
    else:
        file_path = sys.argv[1]
        network_filter = sys.argv[2] if len(sys.argv) == 3 else None
        print(parse_dhcp_leases_json(file_path, network_filter))
