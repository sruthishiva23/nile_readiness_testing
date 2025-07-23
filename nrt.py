#Part 0: Prechecks- Root access, required packages
try:
    import colorlog, logging

    # Create logger
    logger = colorlog.getLogger()
    if logger.hasHandlers():
        logger.handlers.clear()

    # Create formatters
    console_formatter = colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s: %(levelname)s: %(funcName)s: %(lineno)d: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG':    'cyan',
            'INFO':     'green',
            'WARNING':  'yellow',
            'ERROR':    'red',
            'CRITICAL': 'bold_red',
        }
    )
    file_formatter = logging.Formatter('%(asctime)s: %(levelname)s: %(funcName)s: %(lineno)d: %(message)s',
                                     datefmt='%Y-%m-%d %H:%M:%S')

    # Console handler (INFO and above only)
    console_handler = colorlog.StreamHandler()
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)

    # File handler(all levels)
    # Clear previous log file by opening in write mode ('w' instead of default 'a')
    file_handler = logging.FileHandler('nile_readiness.log', mode='w')
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)

    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)

    import os
    import yaml
    import struct
    import time, re, socket
    import random
    import threading
    import ipaddress
    import dhcppython.client as dhcp_client
    import dhcppython.options as dhcp_options
    import dhcppython.utils as dhcp_utils
    from scapy.all import *
    from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
    import ntplib
    import shlex
    import subprocess
    logger.debug('All required packages imported')
except ImportError as e:
    logger.error(f"Error: Required package not found - {str(e)}")
    logger.error("Please install required packages using: pip3 install -r requirements.txt")
    exit(1)

if os.geteuid()!=0:
    logger.error('Must run as root')
    exit(1)
else:
    logger.debug('Running as root')

# Load configuration from YAML file
try:
    with open('config.yaml', 'r') as config_file:
        config = yaml.safe_load(config_file)
        logger.debug("Successfully loaded configuration from config.yaml")
except Exception as e:
    logger.error(f"Failed to load configuration from config.yaml: {e}")
    exit(1)

try:
    # Extract configuration values
    mgmt_interface = config['mgmt_interface']
    test_interface = config['test_network']['test_interface']

    # Network configuration
    ip_address = config['test_network']['ip_address']
    netmask = config['test_network']['netmask']
    gateway = config['test_network']['gateway']

    # Subnet configuration
    nsb_subnet = config['subnets']['nsb']
    sensor_subnet = config['subnets']['sensor']
    client_subnet = config['subnets']['client']

    # Service configuration
    custom_dns_servers = config.get('dns_servers', [])
    custom_ntp_servers = config.get('ntp_servers', [])
    
    # Handle radius configuration - can be dict or empty list
    radius_config = config.get('radius', {})
    if isinstance(radius_config, dict):
        radius_servers = radius_config.get('servers', [])
        radius_user = radius_config.get('user', "")
        radius_password = radius_config.get('password', "")
        radius_secret = radius_config.get('secret', "")
    else:
        # radius is empty list or other type - use empty defaults
        radius_servers = []
        radius_user = ""
        radius_password = ""
        radius_secret = ""
    
    dhcp_servers = config.get('dhcp_servers', [])
except Exception as e:
    logger.error(f"Error extracting configuration values from config.yaml: {e}")
    exit(1)

# Save current state
state = {}

def run_cmd(cmd, check=True, capture_output=True, text=True, shell=False):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=text, shell=shell)


def get_service_name_for_device(device):
    try:
        mac_address = re.search(r'ether (\S+)', run_cmd(f"ifconfig {device}").stdout).group(1)
    except Exception as e:
        logger.error(f"Error getting MAC address for {device}: {e}")
        return None

    services_output = run_cmd("networksetup -listallnetworkservices").stdout
    services = [line.strip().lstrip('*').strip() for line in services_output.splitlines()[1:] if line.strip()]

    for service in services:
        info_output = run_cmd(f'networksetup -getinfo "{service}"').stdout
        if f"Ethernet Address: {mac_address}" in info_output:
            return service
    return None

try:
    interface_initial_state = "up"
    output = run_cmd(f"ifconfig {test_interface}").stdout
    logger.debug(output)
    if '<UP,' not in output.split(f"{test_interface}:")[1].split('\n')[0]:
        interface_initial_state = "down"
        logger.info(f"Bringing up {test_interface}")
        run_cmd(f"ifconfig {test_interface} up", check=False)
        time.sleep(1)
except Exception as e:
    logger.error(f"Error with interface {test_interface}: {e}")
    exit(1)

state['addrs'] = []
output = run_cmd(f"ifconfig {test_interface}").stdout
matches = re.findall(r'inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)', output)
for ip, hex_mask in matches:
    cidr = f"{ip}/{bin(int(hex_mask, 16)).count('1')}"
    state['addrs'].append(cidr)
    logger.debug(f"Found CIDR: {cidr}")

# Save state
with open('state.yaml', 'w') as f:
    yaml.dump(state, f)

# Bring interface back down if needed
if interface_initial_state == "down":
    run_cmd(f"ifconfig {test_interface} down", check=False)
    time.sleep(1)

# Record default routes
state['routes'] = []
output = run_cmd(f"netstat -nrf inet", capture_output=True, text=True).stdout
state['routes'] = [line for line in output.splitlines() if line.startswith('default') or line.startswith('0.0.0.0/0')]
if not state['routes']:
    logger.error(f"No default routes found")
logger.debug(f"Current default routes: {state['routes']}")

interfaces = run_cmd(f"ifconfig -l", capture_output=True, text=True, check=False).stdout.strip().split()
logger.debug(f"All interfaces: {interfaces}")  # Remove default routes from mgmt_interface
if mgmt_interface in interfaces and mgmt_interface != test_interface:
    routes = run_cmd(f"netstat -nrf inet", capture_output=True, text=True).stdout
    routes = [line for line in routes.splitlines() if 'default' in line and mgmt_interface in line]
    logger.debug(f"Default routes on Management interface {mgmt_interface}: {routes}")
    for route in routes:
        logger.info(f"Removing default route {route} from {mgmt_interface}")
        run_cmd(f"route -n delete default {route.split()[1]} -ifp {mgmt_interface}", check=False, capture_output=True)
        run_cmd(f"route -n delete default -ifp {mgmt_interface}", check=False, capture_output=True)
        time.sleep(1) # Wait for route to be removed, if it exists
    routes = run_cmd(f"netstat -nrf inet", capture_output=True, text=True).stdout
    routes = [line for line in routes.splitlines() if 'default' in line and mgmt_interface in line]
    logger.debug(f"Default routes on Management interface {mgmt_interface} after removal: {routes}")
    if routes:
        logger.error(f"Default routes still exist on Management interface {mgmt_interface}")
        exit(1)
else:
    logger.error(f"Management interface {mgmt_interface} not found in list of interfaces: {interfaces}")
    exit(1)

# Recheck if default routes still exist
logger.info("Rechecking if default routes still exist...")
routes = run_cmd(f"netstat -nrf inet", capture_output=True, text=True).stdout
routes = [line for line in routes.splitlines() if 'default' in line]
if len(routes) > 0:
    logger.error(f"Default routes still exist after removal: {routes}")
else:
    logger.info("No default routes found after removal")

with open('state.yaml', 'w') as f:
    yaml.dump(state, f)

# --- Part 2: Configure Test Interface ---
interfaces = run_cmd("ifconfig -l").stdout.strip().split()
if mgmt_interface not in interfaces:
    logger.error(f"Management interface {mgmt_interface} not found")
    exit(1)


# Disable all other interfaces
interfaces_to_disable = [i for i in interfaces if i not in ('lo0', mgmt_interface, test_interface)
                         and not i.startswith(('gif', 'stf', 'awdl', 'llw', 'utun', 'bridge', 'ppp'))]

for iface in interfaces_to_disable:
    logger.info(f"Disabling interface {iface}")
    run_cmd(f"ifconfig {iface} down", check=False)
    time.sleep(1)

# Flush existing IPs on test_interface
try:
    logger.info(f"Getting service name for {test_interface}")
    service_name = get_service_name_for_device(test_interface)
    if not service_name:
        logger.error(f"Could not find Network Service for {test_interface}. Exiting.")
        exit(1)

    # First, disable DHCP (if active) and clear old IP (no direct 'flush', but setting manual IP replaces it)
    logger.info(f"Setting manual IP {ip_address} and netmask {netmask} on '{service_name}'")
    run_cmd(f'networksetup -setmanual "{service_name}" {ip_address} {netmask} {gateway}', check=True)

    # Bring service up (if it was down earlier, it’s already handled elsewhere; otherwise, ensure it’s enabled)
    services_output = run_cmd("networksetup -listallnetworkservices").stdout
    for line in services_output.splitlines():
        if service_name in line and line.strip().startswith('*'):
            logger.info(f"Enabling network service '{service_name}'")
            run_cmd(f'networksetup -setnetworkserviceenabled "{service_name}" on', check=False)
            break

except Exception as e:
    logger.error(f"Error setting IP on {test_interface} via {service_name}: {e}")
    exit(1)

# Verify
time.sleep(5)
output = run_cmd(f"ifconfig {test_interface}").stdout
if ip_address in output:
    logger.info(f"{test_interface} configured with {ip_address}/{netmask}")
else:
    logger.error("Failed to configure interface.")
    exit(1)

# --- Loopback Aliases ---
run_cmd("ifconfig lo0 up", check=False)
state['loopback_ips_added'] = []

for name, subnet_cidr in [('nsb_subnet', nsb_subnet), ('sensor_subnet', sensor_subnet), ('client_subnet', client_subnet)]:
    net = ipaddress.IPv4Network(subnet_cidr)
    first_host = next(net.hosts(), None)
    if first_host:
        alias_netmask = str(net.netmask)
        output = run_cmd("ifconfig lo0").stdout
        if str(first_host) not in output:
            run_cmd(f"ifconfig lo0 inet {first_host} netmask {alias_netmask} alias", check=True)
            state['loopback_ips_added'].append(str(first_host))
            logger.info(f"Added {first_host} to lo0 for {name}")
    else:
        logger.error(f"Subnet {subnet_cidr} too small for loopback alias.")

with open('state.yaml', 'w') as f:
    yaml.dump(state, f)

# --- Add Static Default Route ---
try:
    run_cmd(f"route add default {gateway}", check=True)
except Exception as e:
    logger.error(f"Failed adding default route: {e}")
    exit(1)

# Verify Route
for attempt in range(5):
    output = run_cmd("route -n get default", check=False).stdout
    if gateway in output:
        logger.info(f"Default route to {gateway} active.")
        break
    time.sleep(1)
else:
    logger.error("Failed to verify default route.")
    exit(1)

# --- Set DNS (macOS-Native) ---
try:
    service_name = get_service_name_for_device(test_interface)
    run_cmd(f'networksetup -setdnsservers "{service_name}" 8.8.8.8 8.8.4.4', check=True)
    logger.info("DNS configured via networksetup.")
except Exception as e:
    logger.error(f"DNS configuration failed: {e}")

with open('/etc/resolv.conf') as f:
    state['resolv'] = f.read()

logger.info(f"Current state: {state}")

dns_servers = ['8.8.8.8', '8.8.4.4']
with open('/etc/resolv.conf', 'r+') as f:
    content = f.read()
    for dns in dns_servers + custom_dns_servers:
        if f'nameserver {dns}' not in content:
            f.write(f'\nnameserver {dns}')
            logger.debug(f"Updated /etc/resolv.conf with {dns}")
        else:
            logger.debug(f"DNS {dns} already in /etc/resolv.conf")

# Save state after updating resolv.conf
logger.debug("Saving state after updating resolv.conf")
with open('state.yaml', 'w') as f:
    yaml.dump(state, f, default_flow_style=False)

conf.route.resync()

# Start tcpdump in background
logger.info(f"Starting tcpdump in background on {test_interface}")
cmd = f"tcpdump -i {test_interface} -w packets.pcap &"
subprocess.Popen(['/bin/bash', '-c', cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
logger.info(f"Tcpdump started in background")

# Detect OSPF Hello packets using Scapy
logger.info(f"Detecting OSPF Hello packets on {test_interface}")
pkts = sniff(iface=test_interface, filter='ip proto 89', timeout=15, count=1, store=True)
logger.debug(f"Sniffed {len(pkts)} packets")
if pkts:
    logger.info(f"OSPF Hello packets detected on {test_interface}")
    logger.debug(f"OSPF Hello packet: {pkts[0]}")
    if OSPF_Hdr in pkts[0] and pkts[0][OSPF_Hdr].type == 1 and OSPF_Hello in pkts[0]:
        area_str = str(pkts[0][OSPF_Hdr].area)
        logger.info(f"Detected OSPF Hello from {pkts[0][IP].src} (Area: {area_str}, HelloInt: {pkts[0][OSPF_Hello].hellointerval}s, DeadInt: {pkts[0][OSPF_Hello].deadinterval}s)")
    elif OSPF_Hdr in pkts[0]:
            logger.error(f"Detected non-Hello OSPF packet (Type: {pkts[0][OSPF_Hdr].type}) from {pkts[0][IP].src}")
    else:
        logger.error(f"Detected IP protocol 89 packet from {pkts[0][IP].src}, but not parsed as OSPF Hello.")
else:
    logger.error(f"No OS-PF Hello packets detected on {test_interface}")



# Test 1: DNS Setup and testing

# Update scapy's routing table
conf.route.resync()


# Check if DNS servers are reachable
dns_servers = ['8.8.8.8', '8.8.4.4']
for dns in dns_servers + custom_dns_servers:
    logger.debug(f"Pinging DNS server{dns} from test_interface {ip_address}")
    output = run_cmd(f"ping -c 3 -S {ip_address} {dns}", capture_output=True, text=True)
    if output.returncode == 0:
        logger.info(f"Ping to DNS server {dns} from {ip_address} successful")
    else:
        logger.error(f"Ping to DNS server {dns} from {ip_address} failed: {output.stdout}:{output.stderr}")

# Check if google.com is resolvable
for dns in dns_servers + custom_dns_servers:
    logger.debug(f"Checking if google.com is resolvable from {dns} via {ip_address}")
    r = run_cmd(f'dig @{dns} -b {ip_address} www.google.com +short', capture_output=True, text=True)
    if r.returncode == 0 and bool(r.stdout.strip()):
        logger.info(f"google.com is resolvable from DNS server {dns} via {ip_address}")
        # Add to custom_dns_servers as it is working
        with open('/etc/resolv.conf', 'r+') as f:
            content = f.read()
            if f'nameserver {dns}' not in content:
                f.write(f'\nnameserver {dns}')
    else:
        logger.error(f"google.com is not resolvable from DNS server {dns} via {ip_address}: {r.stdout}:{r.stderr}")

# # Check if each subnet can reach the internet
for subnet_cidr in [nsb_subnet, sensor_subnet, client_subnet]:
    net = ipaddress.IPv4Network(subnet_cidr)
    first_host = next(net.hosts(), None)

    for attempt in range(5):
        output = run_cmd(f"ping -c 2 -S {first_host} 8.8.8.8", capture_output=True, text=True)
        logger.debug(f"Attempt {attempt+1}/5: Ping from {first_host} to {ip_address}- {output.stdout}:{output.stderr}")
        if output.returncode == 0:
            logger.debug("Ping from {first_host} to {ip_address} successful")
            break
        else:
            logger.error(f"Attempt {attempt+1}/5: Ping from {first_host} to {ip_address} failed: {output.stdout}:{output.stderr}")
            time.sleep(2)
            if attempt == 4:
                logger.error(f"ERROR: Failed to ping from {first_host} to {ip_address} after {attempt+1} attempts.")
                exit(1)

# # Ping Tests
for subnet_cidr in [nsb_subnet, sensor_subnet, client_subnet]:
    net = ipaddress.IPv4Network(subnet_cidr)
    first_host = next(net.hosts(), None)
    for dns in dns_servers + custom_dns_servers:
        r = run_cmd(f'dig @{dns} -b {first_host} www.google.com +short', capture_output=True, text=True)
        if r.returncode == 0 and bool(r.stdout.strip()):
            logger.info(f'DNS successfully resolved from {first_host} by DNS server {dns}')
        else:
            logger.error(f'DNS failed to resolve from {first_host} by DNS server {dns}')

# RADIUS Tests
# TODO: Needs Radclient installed on the system
for server in radius_servers:
    logger.info(f'Testing RADIUS server {server}')
    output = run_cmd(f'ping -S {ip_address} -c 1 {server}', capture_output=True)
    if output.returncode != 0:
        logger.error(f'RADIUS {server} cannot be reached: {output.stdout}:{output.stderr}')
        continue
    else:
        logger.debug(f'RADIUS {server} can be reached')

    cmd = ['/bin/bash', '-c', f'radclient -x -s {server}:1812 auth {radius_secret} <<< \'User-Name = "{radius_user}"\nUser-Password = "{radius_password}"\'']
    res = run_cmd(cmd, shell=False, capture_output=True, text=True)
    logger.debug(f'RADIUS response: {res.stdout}')
    if "Passed filter : 1" in res.stdout and "Received Access-Accept" in res.stdout:
        logger.info(f'Authentication to RADIUS {server}: Success')
    else:
        logger.error(f'Authentication to RADIUS {server}: Fail')
        logger.debug(f'RADIUS error output: {res.stderr}')

# NTP Tests
def resolve_hostname_to_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return hostname  # Already an IP
    except ValueError:
        try:
            r = run_cmd(f'dig {hostname} +short', capture_output=True, text=True)
            logger.debug(f"DNS resolution output: {r.stdout}")
            ip = r.stdout.split('\n')[0].strip()
            logger.debug(f"Resolved {hostname} to {ip}")
            return ip
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {hostname}: {e}")
            return None


for ntp_server_host in ['time.google.com', 'pool.ntp.org'] + custom_ntp_servers:
    try:
        client = ntplib.NTPClient()
        resolved_ip = resolve_hostname_to_ip(ntp_server_host)
        if not resolved_ip:
            logger.error(f"Failed to resolve {ntp_server_host} to IP, DNS may not be working")
            continue
        logger.info(f"Resolved {ntp_server_host} to {resolved_ip}")
        response = client.request(resolved_ip, version=3, port=123, timeout=5)
        logger.info(f"Successfully sent NTP request to {ntp_server_host}: Offset {response.offset:.4f}s, without source IP binding")
    except (ntplib.NTPException, socket.timeout, socket.gaierror) as e:
        logger.error(f"NTP query to {ntp_server_host} failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")

for ntp_server_host in ['time.google.com', 'pool.ntp.org'] + custom_ntp_servers:
    resolved_ip = resolve_hostname_to_ip(ntp_server_host)
    if not resolved_ip:
        logger.error(f"Failed to resolve {ntp_server_host} to IP, DNS may not be working")
        continue
    logger.debug(f"Resolved NTP server {ntp_server_host} to {resolved_ip}")
    for source_ip in [ip_address, nsb_subnet, sensor_subnet, client_subnet]:
        logger.debug(f"Testing NTP server {ntp_server_host} with source IP {source_ip}")
        if source_ip != ip_address:
            net = ipaddress.IPv4Network(source_ip)
            source_ip = str(next(net.hosts(), None))
        max_retries = 3
        for attempt in range(max_retries):
            try:
                logger.debug(f"Binding socket to {source_ip} to send NTP request to {ntp_server_host}:{resolved_ip}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((source_ip, 0))
                sock.settimeout(5)

                packet = bytearray(48)
                packet[0] = 0x1B  # LI=0, VN=3, Mode=3

                response = sock.sendto(packet, (resolved_ip, 123))
                if response == 48:
                    logger.debug(f"Received a proper 48-byte NTP response from {ntp_server_host}:{resolved_ip} to {source_ip}")
                else:
                    logger.error(f"Received an invalid NTP response {response} from {ntp_server_host}:{resolved_ip} to {source_ip}")

                data, addr = sock.recvfrom(1024) # Will timeout if server is incorrect or unreachable
                if data:
                    logger.info(f"Successfully received NTP response from {ntp_server_host}:{resolved_ip} to {source_ip} after {attempt+1} attempts")
                    unpacked = struct.unpack("!B B B b 11I", data)
                    logger.debug(f"Success: NTP response from {ntp_server_host}:{resolved_ip} - LVM:{unpacked[0]} Stratum:{unpacked[1]} Poll:{unpacked[2]} Precision:{unpacked[3]} RootDelay:{unpacked[4]} RootDisp:{unpacked[5]} RefID:{unpacked[6]} RefTS:{unpacked[7]},{unpacked[8]} OrigTS:{unpacked[9]},{unpacked[10]} RxTS:{unpacked[11]},{unpacked[12]} TxTS:{unpacked[13]},{unpacked[14]}")
                    break
                else:
                    logger.error(f"No NTP response from {ntp_server_host}:{resolved_ip} to {source_ip} {data} {addr}")
            except socket.timeout:
                logger.error(f"NTP query from {ntp_server_host}:{resolved_ip} to {source_ip} timed out, check if NTP server is correct and reachable")
            except Exception as e:
                logger.error(f"Error sending NTP request using custom socket using source IP {source_ip}: {e}")
            finally:
                sock.close()

            time.sleep(2)


# HTTPS and SSL Certificate Tests
for ip in [ip_address, nsb_subnet, sensor_subnet, client_subnet]:
    if ip != ip_address:
        net = ipaddress.IPv4Network(ip)
        ip = str(next(net.hosts(), None))
    for hostname, issuer in [('ne-u1.nile-global.cloud',"Nile Global Inc."), ("s3.us-west-2.amazonaws.com", "Amazon")]:
        logger.debug(f"Testing TLS connectivity from {ip} to {hostname}:{443}")
        resolved_ip = resolve_hostname_to_ip(hostname)
        if not resolved_ip:
            logger.error(f"Failed to resolve {hostname} to IP, DNS may not be working")
            continue
        output = run_cmd(f'openssl s_client -connect {resolved_ip}:443 -servername {hostname} -bind {ip}', capture_output=True, text=True, check=False)
        logger.debug(f"OpenSSL output: {output.stdout}:{output.stderr}")
        if "issuer=" in output.stdout:
            issuer_start = output.stdout.find("issuer=")
            issuer_end = output.stdout.find("\n", issuer_start)
            issuer_in_cert = output.stdout[issuer_start:issuer_end].strip()
            logger.debug(f"Issuer: {issuer}")
            if issuer in issuer_in_cert:
                logger.info(f"TLS connectivity from {ip} to {hostname}:{443} successful")
            else:
                logger.error(f"TLS connectivity from {ip} to {hostname}:{443} failed: {output.stdout}:{output.stderr}")
        else:
            logger.error(f"TLS connectivity from {ip} to {hostname}:{443} failed: {output.stdout}:{output.stderr}")

# DHCP Tests
# Sniffing function
offer_received = False
def sniff_dhcp_offer():
    logger.info("Sniffing for DHCP Offer packets...")
    sniff(filter="udp and (port 67 or port 68)", prn=dhcp_offer_handler, timeout=10)

# Handler for sniffed packets
def dhcp_offer_handler(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 2:  # 2 = Offer
        logger.debug(f"Successfully received DHCP Offer")
        logger.debug(f"DHCP Offer pkt: {pkt.show(dump=True)}")
        global offer_received
        offer_received = True
    else:
        logger.debug(f"Received non-DHCP Offer packet: {pkt.show(dump=True)}")

client_mac = re.search(r'ether (\S+)', run_cmd(f"ifconfig {test_interface}").stdout).group(1)
client_hostname = run_cmd(f"hostname").stdout.strip()

for dhcp_server in dhcp_servers:
    packet = (IP(src=ip_address, dst=dhcp_server) /
              UDP(sport=67, dport=67) /
              BOOTP(op=1, htype=1, hlen=6, hops=1, xid=0x8fbfaddf, secs=0, flags=0,
                    ciaddr="0.0.0.0", yiaddr="0.0.0.0", siaddr="0.0.0.0",
                    giaddr=ip_address, chaddr=mac2str(client_mac)) /
              DHCP(options=[("message-type", "discover"),
                            ("hostname", client_hostname),
                            ("param_req_list", [1, 3, 6, 15, 51]),
                            "end"]))

    # Run sniffing in a separate thread
    sniff_thread = threading.Thread(target=sniff_dhcp_offer)
    sniff_thread.start()

    # Send the packet
    logger.info(f"Sending DHCP Discover packet to {dhcp_server}")
    send(packet)

    # Wait for the sniffing to complete
    sniff_thread.join()

    if not offer_received:
        logger.error("No DHCP Offer received, check DHCP server connectivity")
    else:
        logger.info("DHCP Offer received, DHCP Relay Connection Successful")

# Load saved state
try:
    with open("state.yaml", "r") as f:
        state = yaml.safe_load(f)
except Exception as e:
    logger.error(f"Failed to load state.yaml: {e}")
    exit(1)

# 1. Restore interface to DHCP
service_name = get_service_name_for_device(test_interface)
if not service_name:
    logger.error("Failed to find network service.")
    exit(1)

logger.info(f"Reverting {service_name} to DHCP")
run_cmd(f'networksetup -setdhcp "{service_name}"', check=False)

# 2. Remove loopback aliases
for ip in state.get('loopback_ips_added', []):
    logger.info(f"Removing loopback alias {ip}")
    run_cmd(f"ifconfig lo0 inet {ip} -alias", check=False)

# 3. Restore default route (remove current and re-add backup route if needed)
try:
    run_cmd("route delete default", check=False)
except Exception:
    pass

logger.info("Removed default route")

for route_line in state.get('routes', []):
    parts = route_line.split()
    if len(parts) >= 2 and parts[0] == 'default':
        gateway_ip = parts[1]
        logger.info(f"Adding default route: route add default {gateway_ip}")
        run_cmd(f"route add default {gateway_ip}", check=False, capture_output=True)
        logger.info(f"Added default route: route add default {gateway_ip}")


# 4. Restore DNS to automatic
logger.info(f"Restoring DNS for {service_name} to automatic")
run_cmd(f'networksetup -setdnsservers "{service_name}" empty', check=False)


# 6. Re-enable all other interfaces (if needed)
interfaces = run_cmd("ifconfig -l").stdout.strip().split()
for iface in interfaces:
    if iface not in ('lo0', test_interface):
        logger.info(f"Re-enabling interface {iface}")
        run_cmd(f"ifconfig {iface} up", check=False)
        time.sleep(0.5)

logger.info(f"Stopping tcpdump")
run_cmd(f"sudo pkill tcpdump", capture_output=True, text=True, check=False)

logger.info("Reversion complete.")
