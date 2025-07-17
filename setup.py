#Part 0: Prechecks- Root access, required packages
# radclient, tcpdump
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
    file_handler = logging.FileHandler('nile_readiness_setup.log', mode='w')
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