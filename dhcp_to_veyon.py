import json
import dhcp_parser
import uuid
import hashlib
import ipaddress
import argparse

def generate_deterministic_uid(name):
    """
    Generates a deterministic UUID based on a given name.

    :param name: String to be hashed (e.g., IP or Room Name)
    :return: UUIDv4-like string
    """
    hash_value = hashlib.md5(name.encode()).hexdigest()
    return str(uuid.UUID(hash_value[:32]))

def veyon_config_return(network_objects=[]):
    """
    Returns the Veyon JSON configuration structure.

    :param network_objects: List of network objects (rooms and hosts).
    :return: Veyon configuration dictionary.
    """
    return {
        "Authentication": {"Method": 1},
        "NetworkObjectDirectory": {"Plugin": "14bacaaa-ebe5-449c-b881-5b382f952571"},
        "BuiltinDirectory": {"NetworkObjects": {"JsonStoreArray": network_objects}}
    }

def get_filtered_room_uid(room_networks, room_uid_map, filter_ip):
    """
    Finds the room UID and name for a given filter IP.

    :param room_networks: List of network CIDRs.
    :param room_uid_map: Dictionary mapping networks to UIDs and room names.
    :param filter_ip: IP address to filter.
    :return: Tuple (room_uid, room_name) if found, otherwise (None, None).
    """
    if not filter_ip:
        return None, None
    
    ip_obj = ipaddress.ip_address(filter_ip)
    for room_network in room_networks:
        if ip_obj in ipaddress.ip_network(room_network, strict=False):
            return room_uid_map[room_network]

    return None, None

def convert_to_veyon(dhcp_data, room_networks, room_names, filter_ip=None, all_rooms=False):
    """
    Converts parsed DHCP lease data into the Veyon JSON configuration format.
    Filters data by room network addresses (CIDR), and optionally by IP address.

    :param dhcp_data: Dictionary obtained from dhcp_parser.parse_lease_content()
    :param room_networks: List of network addresses in CIDR format (e.g., "192.168.1.0/24")
    :param room_names: List of room names assigned to networks
    :param filter_ip: IP address to filter (optional)
    :param all_rooms: If True, include all rooms even if the filter IP is invalid
    :return: Dictionary formatted for Veyon
    """
    if len(room_networks) != len(room_names):
        raise ValueError("The number of room networks must match the number of room names.")

    # Map networks to room UIDs and names
    room_uid_map = {net: (generate_deterministic_uid(name), name) for net, name in zip(room_networks, room_names)}

    # Find the filtered room UID (if applicable)
    filtered_room_uid, _ = get_filtered_room_uid(room_networks, room_uid_map, filter_ip)

    # If filter_ip is set but does not belong to any room and --all is not used, return an empty structure
    if not filtered_room_uid and filter_ip and not all_rooms:
        return veyon_config_return()

    # If filter_ip belongs to a room and --all is not used, include only that room
    if filtered_room_uid and not all_rooms:
        room_networks = [room for room in room_networks if room_uid_map[room][0] == filtered_room_uid]

    network_objects = []

    # Process rooms
    for room_network in room_networks:
        room_uid, room_name = room_uid_map[room_network]

        network_objects.append({
            "Uid": f"{{{room_uid}}}",
            "Type": 2,
            "Name": room_name,
            "glid": 1
        })

        # Process hosts within each room
        for ip, info in dhcp_data["hosts_ip"].items():
            # Ignore same host (infinite screen)
            if filter_ip and ipaddress.ip_address(ip) == ipaddress.ip_address(filter_ip):
                continue

            if ipaddress.ip_address(ip) in ipaddress.ip_network(room_network, strict=False):
                network_objects.append({
                    "Name": info["hostname"],
                    "HostAddress": ip,
                    "MacAddress": info["mac"] if info["mac"] else "",
                    "ParentUid": f"{{{room_uid}}}",
                    "Uid": f"{{{generate_deterministic_uid(ip)}}}",
                    "Type": 3
                })

    return veyon_config_return(network_objects)

def dhcp_to_veyon_json(dhcp_leases_source, room_networks, room_names, filter_ip=None, all_rooms=False, indent=3):
    """
    Converts a DHCP lease file (local or from a URL) to the Veyon JSON configuration format,
    filtering by multiple network addresses (CIDR), and optionally by a specific IP.

    :param dhcp_leases_source: Path to the dhcpd.leases file or a URL
    :param room_networks: List of network addresses in CIDR format to filter results
    :param room_names: List of room names corresponding to the networks
    :param filter_ip: IP address to filter the results by (optional)
    :param all_rooms: If True, include all rooms even if the filter IP is invalid
    :param indent: JSON indentation level (default: 3)
    :return: Formatted JSON string
    """
    dhcp_data = dhcp_parser.parse_dhcp_leases(dhcp_leases_source, active_only=True)
    veyon_config = convert_to_veyon(dhcp_data, room_networks, room_names, filter_ip, all_rooms)
    return json.dumps(veyon_config, indent=indent)

def parse_arguments():
    """
    Parses command-line arguments for the script.
    """
    parser = argparse.ArgumentParser(description="Convert DHCP leases to Veyon JSON configuration.")
    parser.add_argument("-f", "--file", action="append", required=True, help="Path to the dhcpd.leases file or URL")
    parser.add_argument("-n", "--network", action="append", required=True, help="Network address in CIDR format (e.g., 192.168.1.0/24)")
    parser.add_argument("-r", "--room", action="append", required=True, help="Name of the room corresponding to the network")
    parser.add_argument("-a", "--address", help="Filter the configuration by a specific IP address")
    parser.add_argument("--all", action="store_true", help="Include all rooms even if the filter IP is invalid")

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()

    try:
        veyon_json = dhcp_to_veyon_json(args.file, args.network, args.room, args.address, args.all)
        print(veyon_json)
    except Exception as e:
        print(json.dumps(dict(error=repr(e)), indent=3))
