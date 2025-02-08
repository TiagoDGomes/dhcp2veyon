import json
import dhcp_parser
import uuid
import hashlib

def generate_deterministic_uid(name):
    """
    Generate a deterministic UUID based on a given name.

    :param name: String to be hashed (e.g., IP or Room Name)
    :return: UUIDv4-like string
    """
    hash_value = hashlib.md5(name.encode()).hexdigest()  # Gera um hash MD5
    return str(uuid.UUID(hash_value[:32]))  # Converte para UUID válido

def convert_to_veyon(dhcp_data, room_name="Default room"):
    """
    Converts parsed DHCP lease data into the Veyon JSON configuration format.

    :param dhcp_data: Dictionary obtained from dhcp_parser.parse_dhcp_leases()
    :param room_name: Name of the room group (default: "Default room")
    :return: Dictionary formatted for Veyon
    """
    network_objects = []

    # Generate a stable room UID based on the room name
    room_uid = generate_deterministic_uid(room_name)

    # Create the room (group) entry
    network_objects.append({
        "Uid": f"{{{room_uid}}}",
        "Type": 2,
        "Name": room_name,
        "glid": 1
    })

    # Create individual machine entries
    for ip, info in dhcp_data["hosts_ip"].items():
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

def dhcp_to_veyon_json(dhcp_leases_file, network_filter=None, room_name="Default room", indent=3):
    """
    Converts a DHCP lease file to the Veyon JSON configuration format.

    :param dhcp_leases_file: Path to the dhcpd.leases file
    :param network_filter: Network in CIDR format to filter results (optional)
    :param room_name: Name of the room group
    :param indent: JSON indentation level (default: 3)
    :return: Formatted JSON string
    """
    dhcp_data = dhcp_parser.parse_dhcp_leases(dhcp_leases_file, network_filter)
    veyon_config = convert_to_veyon(dhcp_data, room_name)
    return json.dumps(veyon_config, indent=indent)

if __name__ == "__main__":
    import sys

    if len(sys.argv) not in [2, 3, 4]:
        print("Usage: python dhcp_to_veyon.py <path_to_dhcpd.leases> [network_filter] [room_name]")
    else:
        leases_file = sys.argv[1]
        network_filter = sys.argv[2] if len(sys.argv) > 2 else None
        room_name = sys.argv[3] if len(sys.argv) > 3 else "Default room"

        veyon_json = dhcp_to_veyon_json(leases_file, network_filter, room_name)
        print(veyon_json)
