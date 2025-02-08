import json
import dhcp_parser
import uuid
import hashlib
import ipaddress
import argparse
from datetime import datetime

def generate_deterministic_uid(name):
    """
    Generate a deterministic UUID based on a given name.

    :param name: String to be hashed (e.g., IP or Room Name)
    :return: UUIDv4-like string
    """
    hash_value = hashlib.md5(name.encode()).hexdigest()  # Gera um hash MD5
    return str(uuid.UUID(hash_value[:32]))  # Converte para UUID válido

def is_host_active(ends):
    """
    Verifica se o host está ativo com base no tempo de término da concessão (ends).
    
    :param ends: Data de término da concessão no formato 'YYYY/MM/DD HH:MM:SS'
    :return: True se o host estiver ativo, False caso contrário.
    """
    # Converte a data de ends para datetime
    ends_date = datetime.strptime(ends, "%Y/%m/%d %H:%M:%S")
    current_date = datetime.now()
    
    # Compara se a data atual é posterior ao ends
    return current_date < ends_date

def veyon_config_return(network_objects=[]):
    # Final Veyon JSON structure
    veyon_config = {
        "Authentication": {"Method": 1},
        "NetworkObjectDirectory": {"Plugin": "14bacaaa-ebe5-449c-b881-5b382f952571"},
        "BuiltinDirectory": {
            "NetworkObjects": {"JsonStoreArray": network_objects}
        }
    }
    return veyon_config

def convert_to_veyon(dhcp_data, room_networks, room_names, filter_ip=None, all_rooms=False):
    """
    Converts parsed DHCP lease data into the Veyon JSON configuration format.
    Filters data by room network addresses (CIDR), and optionally by IP address.

    :param dhcp_data: Dictionary obtained from dhcp_parser.parse_dhcp_leases()
    :param room_networks: List of network addresses in CIDR format (e.g., "192.168.1.0/24")
    :param room_names: List of room names to be assigned to networks
    :param filter_ip: IP address to filter the output by (optional)
    :param all_rooms: If True, include all rooms even if the filter IP is invalid
    :return: Dictionary formatted for Veyon
    """
    network_objects = []
    room_uid_map = {}

    # Verifica se o número de redes e salas é o mesmo
    if len(room_networks) != len(room_names):
        raise ValueError("The number of room networks must match the number of room names.")

    # Create individual room (group) entries and filter based on room networks
    for room_network, room_name in zip(room_networks, room_names):
        network = ipaddress.ip_network(room_network, strict=False)
        room_uid = generate_deterministic_uid(room_name)
        room_uid_map[room_network] = room_uid, room_name

    # Se o filtro de IP for fornecido, encontramos a rede à qual ele pertence
    filtered_room_uid = None
    filtered_room_name = None
    if filter_ip:
        ip_obj = ipaddress.ip_address(filter_ip)
        found_network = None
        for room_network in room_networks:
            network = ipaddress.ip_network(room_network, strict=False)
            if ip_obj in network:
                filtered_room_uid, filtered_room_name = room_uid_map[room_network]
                found_network = room_network
                break
        
        # Se o IP não pertencer a nenhuma rede e --all não foi fornecido, retorna uma estrutura vazia        
        if not filtered_room_uid and not all_rooms:
                return veyon_config_return()
            
    # Se o IP pertencer a alguma rede e --all não foi fornecido, retorna apenas a rede que pertence
    if filtered_room_uid and not all_rooms:
        room_networks = [found_network,]
        room_names = [filtered_room_name,]

    # Percorre em todas as redes definidas
    for room_network in room_networks:
        network = ipaddress.ip_network(room_network, strict=False)
        room_uid, room_name = room_uid_map[room_network]

        network_objects.append({
            "Uid": f"{{{room_uid}}}",
            "Type": 2,
            "Name": room_name,
            "glid": 1
        })

        for ip, info in dhcp_data["hosts_ip"].items():            
            if ipaddress.ip_address(ip) in network:
                # Verifica se a data ends ainda é válida
                if 'ends' in info and not is_host_active(info['ends']):
                    continue
                network_objects.append({
                    "Name": info["hostname"],
                    "HostAddress": ip,
                    "MacAddress": info["mac"] if info["mac"] else "",
                    "ParentUid": f"{{{room_uid}}}",
                    "Uid": f"{{{generate_deterministic_uid(ip)}}}",  # UID fixo baseado no IP
                    "Type": 3,
                    "Ends": info["ends"]
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
    dhcp_data = dhcp_parser.parse_dhcp_leases(dhcp_leases_source)
    veyon_config = convert_to_veyon(dhcp_data, room_networks, room_names, filter_ip, all_rooms)
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
    parser.add_argument("--all", action="store_true", help="Include all rooms even if the filter IP is invalid")

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_arguments()

    try:
        veyon_json = dhcp_to_veyon_json(args.file, args.network, args.room, args.address, args.all)
        print(veyon_json)
    except ValueError as e:
        print(f"Error: {e}")
