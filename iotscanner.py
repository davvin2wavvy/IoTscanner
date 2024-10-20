import nmap
import socket

# Initialize the Nmap scanner
scanner = nmap.PortScanner()

# Function to automatically detect the local IP address and suggest a network range
def detect_network_range():
    try:
        # Get the local IP address
        host_ip = socket.gethostbyname(socket.gethostname())
        # Assume a /24 network range (adjust if needed)
        network_range = f"{host_ip.rsplit('.', 1)[0]}.0/24"
        return network_range
    except socket.gaierror:
        print("Error: Unable to detect local IP address.")
        return None

# Detect the default network range
default_network = detect_network_range()

# Prompt the user to enter the network IP range or use the detected default
if default_network:
    network_input = input(f"Enter your network IP range (default is {default_network}): ")
else:
    print("Unable to detect your network IP range.")
    network_input = input("Please enter your network IP range (e.g., 192.168.1.0/24): ")
unreachable_hosts = 0  # Variable to keep track of unreachable hosts
scanned_hosts = 0      # Variable to count the number of scanned hosts
max_hosts = 100        # Maximum number of hosts to scan

for host in scanner.all_hosts():
    if scanned_hosts >= max_hosts:
        print(f"\nReached the limit of {max_hosts} hosts. Stopping the scan.")
        break  # Stop scanning after reaching the limit

# Use the default network if no input is provided, otherwise use the user input
network = network_input if network_input else default_network

# If the network variable is still empty, exit
if not network:
    print("No valid network IP range provided. Exiting.")
    exit()

# Scan the network
print(f"Scanning network: {network}")
try:
    scanner.scan(hosts=network, arguments='-p 80,443,1883,1900 -sS -T4 --min-parallelism 100 -n --max-retries 1 --host-timeout 10s')  # -sS: ping scan
except Exception as e:
    print(f"An error occurred during scanning: {e}")
    exit()

unreachable_hosts = 0  # Variable to keep track of unreachable hosts

# Scan for open ports and services
for host in scanner.all_hosts():
    print(f"Performing detailed scan on {host}...")
    detailed_scan = scanner.scan(hosts=host, arguments='-sV')  # -sV: service version detection

# Check if the host exists in the scan results
    if host not in detailed_scan['scan']:
        print(f"No scan data for {host}. Host is unreachable. Skipping...")
        unreachable_hosts += 1  # Increment the unreachable host counter
        continue

    # Check for open ports and services
    if 'tcp' in detailed_scan['scan'][host]:
        for port in detailed_scan['scan'][host]['tcp']:
            service = detailed_scan['scan'][host]['tcp'][port]['name']
            version = detailed_scan['scan'][host]['tcp'][port].get('version', 'unknown')
            print(f"Port {port} is open. Service: {service} Version: {version}")

# Print discovered devices
if scanner.all_hosts():
    for host in scanner.all_hosts():
        if 'mac' in scanner[host]['addresses']:
            print(f"Host: {host} ({scanner[host]['addresses']['mac']})")
        else:
            print(f"Host: {host}")
else:
    print("No hosts found.")

# After the loop, print the number of unreachable hosts
if unreachable_hosts > 0:
    print(f"\nScan complete. {unreachable_hosts} hosts were unreachable.")
else:
    print("\nScan complete. All hosts were reachable.")
