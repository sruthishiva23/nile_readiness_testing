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
    file_handler = logging.FileHandler('nile_readiness_revert.log', mode='w')
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)

    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)

    import os
    import yaml
    import time, re
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
