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

## Usage Instructions

### Important Notes for macOS
- **Root Privileges**: All scripts must be run with `sudo` for network interface management and system configuration
- **Network Interfaces**: Use macOS interface names (typically `en0`, `en1`, etc.) - check with `ifconfig -l`
- **System Integrity Protection**: Some network operations may require SIP configuration on newer macOS versions
- **Terminal Access**: Use Terminal.app or iTerm2 for best compatibility

### Step 1: Prepare Configuration
1. **Check macOS compatibility**: Ensure you're running macOS 11.0+ using `sw_vers`
2. **Install dependencies**: Follow the Homebrew installation guide below
3. **Create virtual environment**: `python3 -m venv venv`
4. **Install Python dependencies**: `source venv/bin/activate && pip install -r requirements.txt`
5. **Create configuration**: Customize `config.yaml` for your macOS network environment
6. **Verify root access**: Test with `sudo whoami` (should return "root")
7. **Check network interfaces**: Use `networksetup -listallhardwareports` to identify interface names

### Step 2: Run Network Setup
```bash
sudo python3 setup.py
```

**Expected Output**:
- Interface configuration messages
- DNS setup confirmation
- Route establishment logs
- Packet capture initialization

### Step 3: Execute Network Tests
```bash
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
# 1. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install macOS Dependencies
brew install freeradius-server
brew install tcpdump bind openssl
brew install coreutils  # Provides updated network utilities

# 4. Verify macOS System Dependencies Installation (If missing, check Prerequisites for more)
command -v radclient >/dev/null 2>&1 && echo "✓ radclient available" || echo "✗ radclient missing"
command -v tcpdump >/dev/null 2>&1 && echo "✓ tcpdump available" || echo "✗ tcpdump missing"  
command -v dig >/dev/null 2>&1 && echo "✓ dig available" || echo "✗ dig missing"
command -v openssl >/dev/null 2>&1 && echo "✓ openssl available" || echo "✗ openssl missing"

# Test built-in macOS tools
command -v ifconfig >/dev/null 2>&1 && echo "✓ ifconfig available" || echo "✗ ifconfig missing"
command -v ping >/dev/null 2>&1 && echo "✓ ping available" || echo "✗ ping missing"
command -v networksetup >/dev/null 2>&1 && echo "✓ networksetup available" || echo "✗ networksetup missing"

# 5. Verify Python environment and modules
python3 -c "import sys; print('Python path:', sys.executable)" && pip list | head -10
python3 -c "import colorlog, yaml, dhcppython, scapy, ntplib; print('✓ All Python modules imported successfully')"

# 6. Configure your environment
cp sample/config.yaml config.yaml
vi config.yaml  # Edit to match your network

# 7. Run the complete test suite
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

## Prerequisites

### System Requirements
- **Operating System**: macOS
  - Tested on macOS 15.4 (Sequoia)
- **Privileges**: Must run as root (`sudo`) for network interface management
- **Python**: Python 3.13+ with pip (use system Python or Homebrew Python)
- **Network Access**: Internet connectivity for testing external services
- **Homebrew**: Package manager for installing additional tools


### Required System Tools

#### Built-in macOS Tools
These tools are included with macOS and should be available by default:
- `ifconfig` - Network interface configuration and management
- `ping` - Network connectivity testing and latency measurement
- `route` - Routing table management and configuration
- `hostname` - System hostname retrieval
- `pkill` - Process termination and management
- `networksetup` - macOS network service configuration utility
- `system_profiler` - System information and hardware details
- `launchctl` - Service and daemon management (for advanced usage)

#### Tools Requiring Installation
Install these via Homebrew:
- `radclient` - RADIUS authentication testing (from FreeRADIUS)
- `tcpdump` - Network packet capture and analysis (may need Homebrew version)
- `dig` - Advanced DNS lookup and resolution testing (from bind)
- `openssl` - SSL/TLS certificate validation and connectivity testing

#### Verify Built-in Tools
```bash
# Test that required built-in tools are available
which ifconfig ping route hostname pkill networksetup
```

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

### macOS System Dependencies Installation

#### Install Homebrew (if not already installed)
```bash
# Install Homebrew package manager
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Verify Homebrew installation
brew --version
```

#### Install Required Tools via Homebrew
```bash
# Update Homebrew to latest version
brew update

# Install FreeRADIUS (provides radclient command)
brew install freeradius-server

# Install additional network tools for enhanced functionality
brew install tcpdump bind openssl

# Optional: Install newer versions of built-in tools
brew install coreutils  # Provides updated network utilities
```

#### Verify Installation
Test that all required tools are available and working:
```bash
# Test Homebrew-installed tools
command -v radclient >/dev/null 2>&1 && echo "✓ radclient available" || echo "✗ radclient missing"
command -v tcpdump >/dev/null 2>&1 && echo "✓ tcpdump available" || echo "✗ tcpdump missing"  
command -v dig >/dev/null 2>&1 && echo "✓ dig available" || echo "✗ dig missing"
command -v openssl >/dev/null 2>&1 && echo "✓ openssl available" || echo "✗ openssl missing"

# Test built-in macOS tools
command -v ifconfig >/dev/null 2>&1 && echo "✓ ifconfig available" || echo "✗ ifconfig missing"
command -v ping >/dev/null 2>&1 && echo "✓ ping available" || echo "✗ ping missing"
command -v networksetup >/dev/null 2>&1 && echo "✓ networksetup available" || echo "✗ networksetup missing"
```

**Verify Python Virtual Environment:**
```bash
# Activate virtual environment and check Python path and packages
source venv/bin/activate
python3 -c "import sys; print('Python path:', sys.executable)" && pip list | head -10
```

Expected output should show:
- Python path pointing to your project's venv directory (e.g., `/Users/username/nile_readiness_testing/venv/bin/python3`)
- Required packages listed: colorlog, dhcppython, ntplib, PyYAML, scapy

#### Troubleshooting Installation
```bash
# Check Mac architecture to determine correct Homebrew path
ARCH=$(uname -m)
echo "Architecture: $ARCH"

# If tools are not found, check PATH
echo $PATH | grep -q "/opt/homebrew/bin\|/usr/local/bin" && echo "Homebrew in PATH" || echo "Add Homebrew to PATH"

# Add Homebrew to PATH based on architecture
if [[ "$ARCH" == "arm64" ]]; then
    # Apple Silicon Macs (M1, M2, M3, etc.)
    echo 'export PATH="/opt/homebrew/bin:$PATH"' >> ~/.zshrc
    echo "Added Apple Silicon Homebrew path"
elif [[ "$ARCH" == "x86_64" ]]; then
    # Intel Macs
    echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.zshrc  
    echo "Added Intel Homebrew path"
fi

# Apply changes and test
source ~/.zshrc
echo "Updated PATH: $PATH"

# Verify Homebrew installation
brew --version && echo "✓ Homebrew working" || echo "✗ Homebrew not found"
```

## macOS-Specific Considerations

### System Integrity Protection (SIP)
Some network operations may be restricted on newer macOS versions:

### Network Service Management
macOS manages network services differently than other Unix systems:
```bash
# View current network service order
networksetup -listnetworkserviceorder

# Temporarily disable other network services during testing (optional)
networksetup -setnetworkserviceenabled "Wi-Fi" off
networksetup -setnetworkserviceenabled "Wi-Fi" on  # Re-enable after testing
```

### Firewall and Security
```bash
# Check firewall status (may interfere with testing)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Temporarily disable firewall for testing (re-enable afterward)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
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

### macOS Interface Identification

#### Identify Available Network Interfaces
```bash
# List all active network interfaces
ifconfig -l
```

#### Map Interfaces to Hardware
```bash
# List all network hardware ports and their interface names
networksetup -listallhardwareports

# Get detailed network service information
networksetup -listallnetworkservices

# Show which interface is primary
route -n get default | grep interface
```

#### Common macOS Interface Names
- `en0` - Usually the primary Ethernet or built-in Wi-Fi
- `en1` - Secondary Ethernet (USB/Thunderbolt adapters)
- `en2`, `en3`, etc. - Additional network adapters
- `lo0` - Loopback interface (localhost)
- `bridge0` - Virtual bridge interfaces
- `utun0`, `utun1` - VPN tunnel interfaces

#### Check Interface Status
```bash
# Check if interface is active and has IP
ifconfig en0 | grep "inet "

# Check interface link status
ifconfig en0 | grep "status:"

# Test interface connectivity
ping -c 3 -I en0 8.8.8.8
```

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

**4. Python Environment and Module Issues**
```bash
# ALWAYS activate virtual environment first
source venv/bin/activate

# Verify Python environment and packages
python3 -c "import sys; print('Python path:', sys.executable)" && pip list | head -10

# Expected output should show:
# - Python path: /Users/username/nile_readiness_testing/venv/bin/python3
# - Required packages: colorlog, dhcppython, ntplib, PyYAML, scapy

# Test module imports
python3 -c "import colorlog, yaml, dhcppython, scapy, ntplib; print('✓ All modules imported successfully')"

# If modules are missing, reinstall
pip install -r requirements.txt
```

**5. Permission Problems (macOS-specific)**
```bash
# Verify root access
sudo whoami  # Should return 'root'

# Check System Integrity Protection status
csrutil status

# Check if networksetup is accessible
sudo networksetup -help >/dev/null && echo "networksetup OK" || echo "networksetup blocked"

# Check file permissions
ls -la config.yaml state.yaml

# Test Homebrew tool access
which radclient dig tcpdump openssl
```

**6. macOS Network Service Issues**
```bash
# Check network service status
networksetup -getinfo "Wi-Fi"
networksetup -getinfo "Ethernet"

# Reset network configuration if needed
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# Check for conflicting VPN connections
scutil --nc list
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

## macOS-Specific Limitations

- **macOS 11.0+ Required**: Scripts use modern macOS `networksetup` and network management commands
- **System Integrity Protection**: Some operations may be restricted on macOS with SIP enabled
- **Single Interface Testing**: Designed for testing one interface at a time
- **Temporary Network Disruption**: May temporarily affect network connectivity and disable other interfaces
- **Administrator Privileges**: Must run with `sudo` for network interface management
- **Interface Dependencies**: Requires specific macOS network interface configuration (en0, en1, etc.)
- **Homebrew Dependency**: Additional tools must be installed via Homebrew package manager
- **macOS Firewall**: Built-in macOS firewall may interfere with network testing

## Support

For issues or questions:
1. Check log files for detailed error messages
2. Ensure all prerequisites are installed
3. Test individual network components manually
