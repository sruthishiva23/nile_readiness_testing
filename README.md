# Nile Network Readiness Testing Suite

## Overview

This suite provides comprehensive network readiness testing for macOS systems, designed to validate network infrastructure components including routing, DNS, RADIUS authentication, NTP synchronization, HTTPS connectivity, and DHCP relay functionality. The suite consists of three main Python scripts that work together to set up a test environment, run extensive network tests, and clean up afterward.

## Components

### 1. `setup.py` - Network Environment Setup
**Purpose**: Configures the macOS system for network testing by setting up interfaces, routing, and DNS.

**Key Functions**:
- Validates root access and required packages
- Configures test network interface with static IP
- Disables unnecessary network interfaces
- Sets up loopback aliases for subnet testing
- Configures DNS servers in `/etc/resolv.conf`
- Establishes static routing via specified gateway
- Starts packet capture (`tcpdump`) for network analysis
- Saves system state for later restoration

### 2. `test.py` - Network Connectivity Testing
**Purpose**: Performs comprehensive network functionality tests across multiple protocols and services.

**Test Categories**:
- **OSPF Detection**: Sniffs for OSPF Hello packets on the test interface
- **DNS Testing**: Validates DNS resolution from multiple source IPs
- **RADIUS Authentication**: Tests authentication against configured RADIUS servers
- **NTP Synchronization**: Validates time synchronization with NTP servers
- **HTTPS/TLS Connectivity**: Tests SSL certificate validation and connectivity
- **DHCP Relay**: Tests DHCP discover/offer functionality

### 3. `revert.py` - System Restoration
**Purpose**: Restores the system to its original network configuration.

**Restoration Tasks**:
- Reverts test interface to DHCP configuration
- Removes loopback IP aliases
- Restores original default routes
- Re-enables previously disabled interfaces
- Restores DNS settings to automatic
- Stops packet capture processes

## Prerequisites

### System Requirements
- **Operating System**: macOS (tested on macOS 14.x+)
- **Privileges**: Must run as root (`sudo`)
- **Python**: Python 3.7+ with pip

### Required Tools
- `networksetup` (built-in macOS tool)
- `ifconfig` (built-in macOS tool)
- `route` (built-in macOS tool)
- `dig` (DNS lookup tool)
- `openssl` (SSL/TLS testing)
- `radclient` (RADIUS testing - install via FreeRADIUS)

### Python Dependencies
Install required packages:
```bash
pip3 install -r requirements.txt
```

**Required packages**:
- `scapy` - Packet manipulation and network testing
- `dhcppython` - DHCP protocol support
- `ntplib` - NTP client functionality
- `colorlog` - Colored logging output
- `pyyaml` - YAML configuration parsing

### Additional Tool Installation
For RADIUS testing, install FreeRADIUS client:
```bash
# macOS with Homebrew
brew install freeradius-server

# This provides the 'radclient' command needed for RADIUS testing
```

## Configuration

### Configuration File: `config.yaml`
Create and customize the configuration file based on your network environment:

```yaml
# Management interface (usually your primary network connection)
mgmt_interface: "en0"

# Test network configuration
test_network:
  test_interface: "en1"        # Interface for testing
  ip_address: "10.132.20.2"    # Static IP for test interface
  netmask: "255.255.255.252"   # Subnet mask
  gateway: "10.132.20.1"       # Default gateway for testing

# Subnet ranges for multi-source testing
subnets:
  nsb: "10.150.88.0/24"        # NSB subnet CIDR
  sensor: "10.150.89.0/24"     # Sensor subnet CIDR  
  client: "10.150.90.0/24"     # Client subnet CIDR

# Optional: Custom DNS servers (in addition to 8.8.8.8, 8.8.4.4)
dns_servers:
  - "10.129.9.193"

# Optional: Custom NTP servers (in addition to time.google.com, pool.ntp.org)
ntp_servers: []

# RADIUS configuration for authentication testing
radius:
  servers:
    - "10.129.4.249"
  user: "testuser"
  password: "testpass"
  secret: "sharedsecret"

# DHCP servers for relay testing
dhcp_servers:
  - "10.129.1.116"
```

### Interface Identification
To identify your network interfaces:
```bash
# List all network interfaces
ifconfig -l

# Get detailed interface information
ifconfig en0  # Replace with your interface name

# List network services and their interfaces
networksetup -listallhardwareports
```

## Usage Instructions

### Step 1: Prepare Configuration
1. Create and customize `config.yaml` for your environment
2. Ensure all required dependencies are installed
3. Verify you have root access

### Step 2: Run Network Setup
```bash
# Set up the test environment
sudo python3 setup.py
```

**Expected Output**:
- Interface configuration messages
- DNS setup confirmation
- Route establishment logs
- Packet capture initialization

### Step 3: Execute Network Tests
```bash
# Run comprehensive network tests
sudo python3 test.py
```

**Expected Output**:
- OSPF packet detection results
- DNS resolution test results
- RADIUS authentication results
- NTP synchronization results
- HTTPS connectivity results
- DHCP relay test results

### Step 4: Restore Original Configuration
```bash
# Clean up and restore original settings
sudo python3 revert.py
```

**Expected Output**:
- Interface restoration messages
- Route cleanup confirmation
- DNS restoration logs
- Interface re-enablement status

### Complete Workflow Example
```bash
# 1. Install dependencies
pip3 install -r requirements.txt

# 2. Configure your environment
cp config.yaml.example config.yaml
vi config.yaml  # Edit to match your network

# 3. Run the complete test suite
sudo python3 setup.py    # Setup test environment
sudo python3 test.py     # Run network tests
sudo python3 revert.py   # Restore original configuration
```

## Log Files

The suite generates detailed log files:
- `nile_readiness_setup.log` - Setup logs
- `nile_readiness.log` - Test execution logs
- `nile_readiness_revert.log` - Restoration process logs
- `packets.pcap` - Network packet capture (created during setup)

## Expected Test Results

### Successful Test Indicators
- **OSPF**: Detection of Hello packets with area and timing information
- **DNS**: Successful resolution of test domains from all source IPs
- **RADIUS**: "Received Access-Accept" messages from RADIUS servers
- **NTP**: Successful time synchronization with offset measurements
- **HTTPS**: Valid SSL certificate validation for test endpoints
- **DHCP**: Receipt of DHCP Offer packets in response to Discover

### Common Failure Scenarios
- **Permission Denied**: Ensure running with `sudo`
- **Interface Not Found**: Verify interface names in `config.yaml`
- **DNS Resolution Failures**: Check DNS server accessibility
- **Timeout Errors**: Verify network connectivity and firewall settings
- **RADIUS Auth Failures**: Verify credentials and server accessibility

## Troubleshooting

### Common Issues

**1. Interface Configuration Errors**
```bash
# Check interface status
ifconfig en1

# Verify network service mapping
networksetup -listallhardwareports
```

**2. DNS Resolution Problems**
```bash
# Test DNS manually
dig @8.8.8.8 google.com

# Check current DNS settings
cat /etc/resolv.conf
```

**3. Routing Issues**
```bash
# Check current routes
netstat -rn

# Test gateway connectivity
ping 10.132.20.1
```

**4. Permission Problems**
```bash
# Verify root access
sudo whoami  # Should return 'root'

# Check file permissions
ls -la config.yaml state.yaml
```

### Recovery from Failed Tests

If the test suite fails and doesn't complete reversion:

```bash
# Manual cleanup commands
sudo python3 revert.py  # Attempt automatic reversion

# If automatic reversion fails, manual cleanup:
sudo networksetup -setdhcp "Your Network Service Name"
sudo route delete default
sudo ifconfig lo0 10.150.88.1 -alias  # Remove loopback aliases
sudo pkill tcpdump  # Stop packet capture
```

## Security Considerations

- Scripts require root privileges for network configuration
- Temporarily disables network interfaces during testing
- Modifies system network configuration and routing tables
- Creates network packet captures that may contain sensitive data
- RADIUS credentials are passed as command-line arguments (visible in process lists)

## Limitations

- **macOS Only**: Scripts use macOS-specific `networksetup` commands
- **Single Interface Testing**: Designed for testing one interface at a time
- **Temporary Network Disruption**: May temporarily affect network connectivity
- **Root Required**: Cannot run with standard user privileges
- **Interface Dependencies**: Requires specific network interface configuration

## Support

For issues or questions:
1. Check log files for detailed error messages
2. Verify configuration file syntax and values
3. Ensure all prerequisites are installed
4. Test individual network components manually
5. Review network infrastructure requirements
