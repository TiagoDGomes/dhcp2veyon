from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import ipaddress
import os
import logging
from dhcp_to_veyon import dhcp_to_veyon_json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    from settings import LEASE_FILES, ROOM_NETWORKS, ROOM_NAMES
except ModuleNotFoundError:
    logging.error("File settings.py not found! Make a copy of settings.py-example as settings.py and edit the file.")
    exit(1)
except ImportError as ie:
    logging.error(f"Import error: {ie}")
    exit(1)

class VeyonConfigHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        try:
            config = dhcp_to_veyon_json(LEASE_FILES, ROOM_NETWORKS, ROOM_NAMES, client_ip)
            self.send_response(200)
        except Exception as e:
            logging.error(f"Error processing request from {client_ip}: {e}")
            config = json.dumps({"error": str(e)})
            self.send_response(500)
        
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(config.encode("utf-8"))

if __name__ == "__main__":
    try:
        port = int(os.getenv("VEYON_HTTP_PORT", 8080))  # Get port from environment variable, default to 8080
        if not (1 <= port <= 65535):
            raise ValueError("Port number must be between 1 and 65535.")
        
        server_address = ("", port)  # Listen on all available interfaces
        httpd = HTTPServer(server_address, VeyonConfigHandler)
        logging.info(f"Veyon DHCP Server running on port {port}...")
        httpd.serve_forever()
    except ValueError as ve:
        logging.error(f"Invalid port number: {ve}")
        exit(1)
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
        httpd.server_close()
    except OSError as e:
        logging.error(f"Failed to start server: {e}")
        exit(1)
    except SystemExit:
        logging.info("Server exiting...")
        exit(0)
