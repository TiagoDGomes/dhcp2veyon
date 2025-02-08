from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import ipaddress
import os
from dhcp_to_veyon import dhcp_to_veyon_json

try:
    from settings import LEASE_FILES, ROOM_NETWORKS, ROOM_NAMES
except ModuleNotFoundError:
    exit("File settings.py not found! Make a copy of settings.py-example as settings.py and edit the file.")
except ImportError as ie:
    exit(str(ie))

class VeyonConfigHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.strip('/')
        client_ip = self.client_address[0]
        all_rooms = path.lower() == "all"
        
        try:
            config = dhcp_to_veyon_json(LEASE_FILES, ROOM_NETWORKS, ROOM_NAMES, None if all_rooms else client_ip, all_rooms)
            self.send_response(200)
        except Exception as e:
            config = json.dumps({"error": str(e)})
            self.send_response(500)
        
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(config.encode("utf-8"))

if __name__ == "__main__":
    port = int(os.getenv("VEYON_HTTP_PORT", 8080))  # Get port from environment variable, default to 8080
    server_address = ("", port)  # Listen on all available interfaces
    try:
        httpd = HTTPServer(server_address, VeyonConfigHandler)
        print(f"Veyon DHCP Server running on port {port}...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down server...")
        httpd.server_close()
    except OSError as e:
        print(f"Failed to start server: {e}")
        exit(1)
