import socket
import sys
import platform
import struct
import os

def scan_host(host, port, r_code=1):
    try:
        # Create a new socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set timeout to 1 second
        sock.settimeout(1)
        # Connect to the host and port
        result = sock.connect_ex((host, port))
        # Check if the connection was successful
        if result == 0:
            r_code = 0
    except Exception as e:
        pass
    return r_code

def get_service(port):
    # Dictionary of common ports and their associated services
    services = {
        22: 'SSH',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        8080: 'HTTP Alternate'
    }
    # Return the service name if the port is found in the dictionary, otherwise return 'Unknown'
    return services.get(port, 'Unknown')

def get_os(host):
    # Get the raw response from the ICMP echo request
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
socket.IPPROTO_ICMP)
        my_socket.settimeout(1)
        my_socket.connect((host, 80))
        my_socket.sendall(struct.pack("!BBHHH", 8, 0, 0, 1, 1))
        response = my_socket.recv(1024)
        my_socket.close()
        # Parse the response to get the operating system name
        os = platform.uname()[0]
        if os == 'Windows':
            return 'Windows'
        elif os == 'Linux':
            return 'Linux'
        elif os == 'Darwin':
            return 'MacOS'
        else:
            return 'Unknown'
    except Exception as e:
        return 'Unknown'

def scan_arp_table(host):
    arp_table = os.popen("arp -a " + host).read()
    if host in arp_table:
        return True
    else:
        return False

def scan_ports(host, ports):
    # Dictionary to store open ports
    open_ports = {}
    # Scan each port
    for port in ports:
        response = scan_host(host, port)
        if response == 0:
            open_ports[port] = get_service(port)
    return open_ports

def scan_network(host, ports):
    print('Scanning host:', host)
    open_ports = scan_ports(host, ports)
    if len(open_ports) == 0:
        print('No open ports found for host:', host)
    else:
        print('Open ports:', open_ports)
    os = get_os(host)
    print('Detected OS:', os)
    arp_check = scan_arp_table(host)
    if arp_check:
        print("Host found in ARP table")
    else:
        print

if __name__ == '__main__':
    host = input('Enter the host IP: ')
    ports = input('Enter the ports separated by comma: ')
    ports = [int(x) for x in ports.split(',')]
    scan_network(host, ports)

