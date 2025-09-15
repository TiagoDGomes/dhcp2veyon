# dhcp2veyon

This system aims to convert DHCP lease data into a JSON format compatible with Veyon configuration.
The tool allows filtering data by network and room, and it can also be configured to display only the room to which a specific IP belongs.

## Features

- **Conversion of DHCP lease files to Veyon JSON format**: From a DHCP lease file, the system generates a JSON file in the format expected by Veyon.
- **Filtering by network (CIDR)**: You can specify one or more CIDR networks (e.g., `192.168.1.0/24`) to filter the machines and rooms to be included in the configuration.
- **Filtering by IP address**: With the `-a` option, you can filter results to include only the room where the provided IP is located.
- **Excluding other rooms**: When the `-a` option is used, the system ensures that only the hosts in the room associated with the provided IP are displayed, excluding all other rooms.
- **Empty return in case of invalid IP**: When a provided IP does not belong to any network and the --all option is not active, the system returns an empty configuration while preserving the Veyon JSON structure with an empty JsonStoreArray field.

## Installation

### Requirements
- Python 3.6 or higher

### Dependency installation

There are no dependencies.

### DHCP lease file

The system input must be a DHCP lease file, which can be obtained directly from a DHCP server or exported from a system that provides it. The input can be either a local file path or a URL.

## Using the HTTP version
The HTTP version is the most practical way to obtain the Veyon configuration to be deployed on the teacher’s computer.

### Editing default values
- Make a copy of the `settings.py-example` file and rename it to `settings.py`;
- Edit the `settings.py` file according to your network characteristics.

### Starting the HTTP server
The following code shows an example of how to start the HTTP server on port 80 (replace the port if needed):

```bash
VEYON_HTTP_PORT=80 python3 http_server.py
```

### List of available URLs

- `/veyon`: Returns the configuration of the room based on the IP that accessed the resource (used for the teacher’s computer).
- `/veyon/all`: Returns the configuration of all configured rooms.

### Setting up the teacher’s computer
You need to create a script that periodically updates the Veyon configuration.

#### On Windows
Use Task Scheduler to run the following PowerShell script as administrator:

```powershell
iwr http://my-server/veyon -OutFile C:\WINDOWS\Temp\veyon.json
& "C:\Program Files\Veyon\veyon-cli.exe" config import C:\WINDOWS\Temp\veyon.json
Restart-Service -Name VeyonService
```

#### On Linux
Use cron as root to run the following bash script:

```bash
VEYON_CONFIG_FILE="/tmp/.config.json"
wget "http://my-server/veyon" -O $VEYON_CONFIG_FILE -q
veyon-cli config import $VEYON_CONFIG_FILE
systemctl restart veyon
```

## Using the CLI version

The script can be executed as follows:

```bash
python3 dhcp_to_veyon.py -f "<path_to_dhcpd.leases>" -n "<network1>" -n "<network2>" -r "<room1>" -r "<room2>" [-a "<ip_address>"] [--all]
```

### Parameters

- `-f <file_path>`: Path to the DHCP lease file or URL containing the lease data.
- `-n <network>`: Network address in CIDR format (e.g.,`192.168.1.0/24`). Can be used multiple times to specify several networks.
- `-r <room>`: Room or group name. Can be used multiple times to associate multiple networks with different rooms.
- `-a <ip_address>`: Filter for a specific IP. If provided, the script will return only the configuration of the room where the IP is present.
- `--all`: If provided, it will include all rooms, even if the filtered IP does not belong to any specified network.

### Usage examples

1. **Simple DHCP-to-Veyon JSON conversion:**:

```bash
python3 dhcp_to_veyon.py -f "dhcpd.leases" -n "10.1.2.0/24" -n "10.1.3.0/24" -r "Room 2" -r "Room 3"
```

This will generate a JSON file with configurations for the networks 10.1.2.0/24 and 10.1.3.0/24, associated with rooms "Room 2" and "Room 3".

2. **Filtering by IP (returns the room with the provided IP)**:

```bash
python3 dhcp_to_veyon.py -f "dhcpd.leases" -n "10.1.2.0/24" -n "10.1.3.0/24" -r "Room 2" -r "Room 3" -a "10.1.2.200"
```
This will return only the machines in "Room 2", excluding any machines associated with other networks or rooms.

3. **When the provided IP does not belong to any network and --all is not provided**:

```bash
python3 dhcp_to_veyon.py -f "dhcpd.leases" -n "10.1.2.0/24" -n "10.1.3.0/24" -r "Room 2" -r "Room 3" -a "10.1.4.200"
```

This will result in an empty configuration with the Veyon structure and an empty JsonStoreArray.

4. **With the --all option, all rooms will be included, even if the IP is not found in any network**:
```bash
python3 dhcp_to_veyon.py -f "dhcpd.leases" -n "10.1.2.0/24" -n "10.1.3.0/24" -r "Room 2" -r "Room 3" -a "10.1.4.200" --all
```
This will return all rooms, including "Room 2" and "Room 3", even if IP 10.1.4.200 does not belong to any network.




