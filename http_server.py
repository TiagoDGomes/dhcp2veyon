from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import ipaddress
import os
import logging
from dhcp_to_veyon import dhcp_to_veyon_json
from dhcp_parser import address_info

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    from settings import LEASE_FILES, ROOMS
except ModuleNotFoundError:
    logging.error("File settings.py not found! Make a copy of settings.py-example as settings.py and edit the file.")
    exit(1)
except ImportError as ie:
    logging.error(f"Import error: {ie}")
    exit(1)

class DHCPConfigHandler(BaseHTTPRequestHandler):
    def config_veyon(self, split_path, client_ip):
        classroom_networks = [room[0] for room in ROOMS if room[2]]
        classroom_names = [room[1] for room in ROOMS if room[2]]  
        try:                     
            all_rooms = split_path[1] == "all"
            client_ip = split_path[1] if not all_rooms else client_ip
        except IndexError:
            all_rooms = False        
        config = dhcp_to_veyon_json(LEASE_FILES, classroom_networks, classroom_names, (None if all_rooms else client_ip), all_rooms)
        return config
    
    def info_address(self, split_path, client_ip):   
        if split_path[0] == "address" and len(split_path) > 1:
            client_ip = split_path[1] 
        addr_info = address_info(LEASE_FILES, client_ip)
        for room_network, room_name, is_classroom in ROOMS:
            if ipaddress.ip_address(client_ip) in ipaddress.ip_network(room_network, strict=False):
                addr_info["network-description"] = room_name
                addr_info["network"] = room_network
                break        
        config = json.dumps(addr_info, indent=3)
        return config
        
    def do_GET(self):
        path = self.path.strip('/')
        client_ip = self.client_address[0]       
        
        # Log the incoming request
        logging.info(f"Received request from {client_ip} for path {path}")
        config = ''
        split_path = path.lower().split('/')
        try:
            if split_path[0] == "veyon":             
                config = self.config_veyon(split_path, client_ip)
            else:
                config = self.info_address(split_path, client_ip)            
            self.send_response(200)
        except Exception as e:
            # Log the error
            logging.error(f"Error processing request: {str(e)}")
            config = json.dumps({"error": f"{str(e)}"})
            self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(config.encode("utf-8"))

if __name__ == "__main__":
    port = int(os.getenv("VEYON_HTTP_PORT", 8080))  # Get port from environment variable, default to 8080

    # Validate port
    if not (1 <= port <= 65535):
        logging.error("Invalid port number: Port must be between 1 and 65535.")
        exit(1)

    server_address = ("", port)  # Listen on all available interfaces
    
    try:
        httpd = HTTPServer(server_address, DHCPConfigHandler)
        logging.info(f"Veyon DHCP Server running on port {port}...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
        httpd.server_close()
    except OSError as e:
        logging.error(f"Failed to start server: {e}")
        exit(1)
    except SystemExit:
        logging.info("Server exiting...")
        exit(0)