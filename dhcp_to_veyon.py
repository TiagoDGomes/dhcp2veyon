import json
import dhcp_parser
import uuid
import hashlib
import ipaddress
import argparse

def generate_deterministic_uid(name):
    """
    Generate a deterministic UUID based on a given name.

    :param name: String to be hashed (e.g., IP or Room Name)
    :return: UUIDv4-like string
    """
    hash_value = hashlib.md5(name.encode()).hexdigest()  # Gera um hash MD5
    return str(uuid.UUID(hash_value[:32]))  # Converte para UUID válido

def convert_to_veyon(dhcp_data, room_networks, room_names, filter_ip=None):
    """
    Converts parsed DHCP lease data into the Veyon JSON configuration format.
    Filters data by room network addresses (CIDR), and optionally by IP address.

    :param dhcp_data: Dictionary obtained from dhcp_parser.parse_dhcp_leases()
    :param room_networks: List of network addresses in CIDR format (e.g., "192.168.1.0/24")
    :param room_names: List of room names to be assigned to networks
    :param filter_ip: IP address to filter the output by (optional)
    :return: Dictionary formatted for Veyon
    """
    network_objects = []

    # Verifica se o número de redes e salas é o mesmo
    if len(room_networks) != len(room_names):
        raise ValueError("The number of room networks must match the number of room names.")

    # Create individual room (group) entries and filter based on room networks
    for room_network, room_name in zip(room_networks, room_names):
        network = ipaddress.ip_network(room_network, strict=False)
        room_uid = generate_deterministic_uid(room_name)

        # Create the room (group) entry
        network_objects.append({
            "Uid": f"{{{room_uid}}}",
            "Type": 2,
            "Name": room_name,
            "glid": 1
        })

        # Create individual machine entries within the current network range
        for ip, info in dhcp_data["hosts_ip"].items():
            if ipaddress.ip_address(ip) in network:  # Verifica se o IP pertence à rede
                # Se um IP de filtro for fornecido e for o mesmo que o IP do host, pula esse host
                if filter_ip and ip == filter_ip:
                    continue
                network_objects.append({
                    "Name": info["hostname"],
                    "HostAddress": ip,
                    "MacAddress": info["mac"] if info["mac"] else "",
                    "ParentUid": f"{{{room_uid}}}",
                    "Uid": f"{{{generate_deterministic_uid(ip)}}}",  # UID fixo baseado no IP
                    "Type": 3
                })

    # Final Veyon JSON structure
    veyon_config = {
        "Authentication": {"Method": 1},
        "NetworkObjectDirectory": {"Plugin": "14bacaaa-ebe5-449c-b881-5b382f952571"},
        "BuiltinDirectory": {
            "NetworkObjects": {"JsonStoreArray": network_objects}
        }
    }

    return veyon_config

def dhcp_to_veyon_json(dhcp_leases_source, room_networks, room_names, filter_ip=None, indent=3):
    """
    Converts a DHCP lease file (local or from a URL) to the Veyon JSON configuration format,
    filtering by multiple network addresses (CIDR), and optionally by a specific IP.

    :param dhcp_leases_source: Path to the dhcpd.leases file or a URL
    :param room_networks: List of network addresses in CIDR format to filter results
    :param room_names: List of room names corresponding to the networks
    :param filter_ip: IP address to filter the results by (optional)
    :param indent: JSON indentation level (default: 3)
    :return: Formatted JSON string
    """
    dhcp_data = dhcp_parser.parse_dhcp_leases(dhcp_leases_source)
    veyon_config = convert_to_veyon(dhcp_data, room_networks, room_names, filter_ip)
    return json.dumps(veyon_config, indent=indent)

def parse_arguments():
    """
    Parse command-line arguments for the script.
    """
    parser = argparse.ArgumentParser(description="Convert DHCP leases to Veyon JSON configuration.")
    parser.add_argument("-f", "--file", required=True, help="Path to the dhcpd.leases file or URL")
    parser.add_argument("-n", "--network", action="append", required=True, help="Network address in CIDR format (e.g., 192.168.1.0/24)")
    parser.add_argument("-r", "--room", action="append", required=True, help="Name of the room corresponding to the network")
    parser.add_argument("-a", "--address", help="Filter the configuration by a specific IP address")
    
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_arguments()

    try:
        veyon_json = dhcp_to_veyon_json(args.file, args.network, args.room, args.address)
        print(veyon_json)
    except ValueError as e:
        print(f"Error: {e}")
