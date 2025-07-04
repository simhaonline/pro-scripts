# AlmaLinux 9+ Production Bootstrap Script

[![License](https://img.shields.io/badge/License-Production%20Use%20Allowed-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2025.07.04-blue.svg)](https://github.com/simhaonline/pro-scripts)
[![AlmaLinux](https://img.shields.io/badge/AlmaLinux-9%2B-red.svg)](https://almalinux.org/)

A comprehensive, production-grade bootstrap script for AlmaLinux 9+ servers with advanced features including stage-based execution, rollback support, and enterprise-ready configuration management.

## 🚀 Quick Start

```bash
# Download and run interactively
curl -fsSL https://raw.githubusercontent.com/simhaonline/pro-scripts/main/bootstrap.sh -o bootstrap.sh
chmod +x bootstrap.sh
sudo ./bootstrap.sh
```

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Stage System](#-stage-system)
- [Examples](#-examples)
- [Advanced Features](#-advanced-features)
- [Troubleshooting](#-troubleshooting)
- [Security](#-security)
- [Contributing](#-contributing)

## ✨ Features

### 🔧 Core System Configuration
- **SELinux Configuration**: Secure permissive mode setup
- **Hostname Management**: FQDN support with public IP detection
- **User Management**: Smart user creation with existing user detection
- **Package Management**: DNF optimization and repository configuration
- **System Updates**: Automated security updates with configurable policies

### 🌐 Network & Connectivity
- **Automatic IP Detection**: Public IPv4 and IPv6 address discovery
- **Hosts File Management**: Comprehensive local and public IP mapping
- **Time Synchronization**: Geographic timezone detection with NTP setup
- **Firewall Configuration**: Multi-backend support (firewalld, UFW, iptables)

### 🖥️ Hardware Optimization
- **CPU Detection**: Automatic Intel/AMD processor identification
- **Virtualization Support**: KVM modules with nested virtualization
- **Kernel Modules**: Performance optimization and container support
- **Network Tuning**: BBR congestion control and advanced TCP settings

### 📊 Monitoring & Management
- **Cockpit Web UI**: Modern web-based system management
- **PCP Monitoring**: Performance metrics with Prometheus export
- **Log Management**: Structured logging with rotation policies
- **Status Tracking**: Comprehensive system state monitoring

### 🛡️ Enterprise Features
- **Stage-Based Execution**: Granular control with resumption support
- **Rollback Capability**: Complete configuration rollback with backups
- **Configuration Management**: Save/load settings with environment files
- **JSON Logging**: Structured output for automation and monitoring
- **Lock Management**: Process-safe execution with stale lock cleanup

## 🔧 Installation

### Prerequisites
- AlmaLinux 9 or higher
- Root or sudo access
- Internet connectivity for package downloads

### Download Methods

#### Method 1: Direct Download
```bash
curl -fsSL https://raw.githubusercontent.com/simhaonline/pro-scripts/main/bootstrap.sh -o bootstrap.sh
chmod +x bootstrap.sh
```

#### Method 2: Git Clone
```bash
git clone https://github.com/simhaonline/pro-scripts.git
cd almalinux-bootstrap
chmod +x bootstrap.sh
```

#### Method 3: Wget
```bash
wget https://raw.githubusercontent.com/simhaonline/pro-scripts/main/bootstrap.sh
chmod +x bootstrap.sh
```

## 🎯 Usage

### Basic Usage

#### Interactive Mode (Recommended)
```bash
sudo ./bootstrap.sh
```
- Prompts for hostname, passwords, and configuration options
- Provides real-time feedback and progress updates
- Allows for configuration review before execution

#### Non-Interactive Mode
```bash
sudo ./bootstrap.sh -n
```
- Uses default configurations
- Suitable for automated deployments
- No user interaction required

### Command Line Options

```bash
Usage: ./bootstrap.sh [OPTIONS]

OPTIONS:
    -h, --help                  Show help message
    -v, --version               Show script version
    -n, --non-interactive       Run in non-interactive mode
    -H, --hostname HOSTNAME     Set system hostname (FQDN recommended)
    -u, --sysadmin-user USER    Set sysadmin username (default: sysadmin)
    -p, --sysadmin-pass PASS    Set sysadmin password
    -r, --root-pass PASS        Set root password
    --load-config               Load configuration from saved file
    --json-logging              Enable JSON formatted logging
    --stage MODULE              Run only specific stage
    --force-stage               Force run stage even if completed
    --reset-state               Reset all stage completion state
    --show-state                Show current stage completion state
    --skip-MODULE               Skip specific module
    --rollback                  Perform rollback from backup
    --list-backups              List available backups
```

### Skip Options
```bash
--skip-selinux              Skip SELinux configuration
--skip-hostname             Skip hostname configuration
--skip-users                Skip user creation/configuration
--skip-dnf-tuning           Skip DNF configuration tuning
--skip-repos                Skip repository configuration
--skip-updates              Skip system updates
--skip-tools                Skip tools installation
--skip-auto-updates         Skip auto-updates configuration
--skip-time-sync            Skip time synchronization
--skip-kernel-modules       Skip kernel modules configuration
--skip-cockpit              Skip Cockpit web management
--skip-rollback             Skip rollback support setup
--skip-reboot-prompt        Skip reboot prompt at end
```

## ⚙️ Configuration

### Configuration Files

#### Main Configuration: `/etc/bootstrap-config.env`
```bash
# Generated configuration file
SYSADMIN_USER="admin"
HOSTNAME="server.example.com"
COCKPIT_PORT="9090"
PCP_EXPORT_PORT="44322"
# ... additional settings
```

#### Stage State: `/opt/bootstrap/state`
```bash
# Stage tracking file
stage:hostname:completed:2025-07-04 15:30:25
stage:users:running:2025-07-04 15:32:10
stage:kernel-modules:failed:2025-07-04 15:35:45
```

#### Status Tracking: `/var/lib/bootstrap-status.json`
```json
{
  "modules": {
    "hostname": {
      "status": "completed",
      "timestamp": "2025-07-04 15:30:25"
    }
  },
  "last_run": "2025-07-04 15:40:00",
  "version": "2025.07.04"
}
```

### Default Settings

| Setting | Default Value | Description |
|---------|---------------|-------------|
| `SYSADMIN_USER` | `sysadmin` | Administrative user name |
| `SYSADMIN_PASS` | `5imhA#2025` | Default admin password |
| `ROOT_PASS` | `M3hU!#2025` | Default root password |
| `COCKPIT_PORT` | `9090` | Cockpit web interface port |
| `PCP_EXPORT_PORT` | `44322` | Prometheus metrics port |
| `FALLBACK_TIMEZONE` | `UTC` | Default timezone if detection fails |

## 🏗️ Stage System

### Available Stages

| Stage | Description | Dependencies |
|-------|-------------|--------------|
| `selinux` | SELinux configuration | None |
| `hostname` | Hostname and network setup | None |
| `users` | User creation and management | None |
| `dnf` | DNF package manager tuning | None |
| `repos` | Repository configuration | None |
| `updates` | System updates | `repos` |
| `tools` | Essential tools installation | `repos` |
| `auto-updates` | Automatic updates setup | `repos` |
| `time-sync` | Time synchronization | `tools` |
| `kernel-modules` | Kernel modules and optimization | `tools` |
| `cockpit` | Cockpit web management | `users`, `tools` |

### Stage Management

#### View Current State
```bash
./bootstrap.sh --show-state
```

#### Run Specific Stage
```bash
./bootstrap.sh --stage hostname
```

#### Force Re-run Completed Stage
```bash
./bootstrap.sh --stage users --force-stage
```

#### Reset All State
```bash
./bootstrap.sh --reset-state
```

### Stage States

- **`pending`**: Stage not yet executed
- **`running`**: Stage currently executing
- **`completed`**: Stage successfully finished
- **`failed`**: Stage encountered an error

## 💡 Examples

### Basic Deployment
```bash
# Standard interactive deployment
sudo ./bootstrap.sh

# Non-interactive with custom hostname
sudo ./bootstrap.sh -n -H web01.example.com

# Custom user and passwords
sudo ./bootstrap.sh -u admin -p SecurePass123 -r RootPass456
```

### Advanced Deployment
```bash
# Load saved configuration
sudo ./bootstrap.sh --load-config

# JSON logging for automation
sudo ./bootstrap.sh --json-logging -n

# Skip specific components
sudo ./bootstrap.sh --skip-updates --skip-cockpit

# Selective execution
sudo ./bootstrap.sh --stage kernel-modules --stage cockpit
```

### Maintenance Operations
```bash
# Check deployment status
sudo ./bootstrap.sh --show-state

# Retry failed stage
sudo ./bootstrap.sh --stage updates --force-stage

# Complete rollback
sudo ./bootstrap.sh --rollback

# List available backups
sudo ./bootstrap.sh --list-backups
```

### Automation Examples
```bash
# CI/CD Pipeline
sudo ./bootstrap.sh -n --json-logging --skip-reboot-prompt

# Staged Deployment
sudo ./bootstrap.sh --stage users --stage hostname -n
sudo ./bootstrap.sh --stage tools --stage cockpit -n

# Recovery Scenario
sudo ./bootstrap.sh --reset-state
sudo ./bootstrap.sh --load-config
```

## 🚀 Advanced Features

### Configuration Management

#### Save Configuration
```bash
# Configuration is automatically saved to /etc/bootstrap-config.env
# Load with: --load-config
```

#### Environment Variables
```bash
# Set via environment
export SYSADMIN_USER="admin"
export HOSTNAME="server.domain.com"
./bootstrap.sh --load-config
```

### Stage-Based Execution

#### Resume After Interruption
```bash
# If script is interrupted, simply re-run
sudo ./bootstrap.sh
# Automatically resumes from where it left off
```

#### Selective Updates
```bash
# Update only specific components
sudo ./bootstrap.sh --stage updates --force-stage
sudo ./bootstrap.sh --stage kernel-modules --force-stage
```

### Rollback System

#### Automatic Backups
- Configuration files backed up before changes
- Complete system state snapshot
- Rollback script generation

#### Rollback Process
```bash
# List available backups
sudo ./bootstrap.sh --list-backups

# Perform rollback
sudo ./bootstrap.sh --rollback /var/backups/bootstrap-20250704_143022
```

### JSON Logging

#### Enable JSON Output
```bash
sudo ./bootstrap.sh --json-logging
```

#### Sample JSON Output
```json
{
  "timestamp": "2025-07-04T15:30:25.123Z",
  "level": "INFO",
  "message": "Stage hostname completed successfully",
  "script": "bootstrap.sh",
  "version": "2025.07.04"
}
```

## 🔍 Troubleshooting

### Common Issues

#### Permission Errors
```bash
# Ensure script is run as root
sudo ./bootstrap.sh

# Check file permissions
ls -la bootstrap.sh
chmod +x bootstrap.sh
```

#### Network Issues
```bash
# Check internet connectivity
ping -c 3 google.com

# Verify DNS resolution
nslookup pool.ntp.org
```

#### Stage Failures
```bash
# Check stage status
./bootstrap.sh --show-state

# Review logs
tail -f /var/log/bootstrap-*.log

# Retry failed stage
./bootstrap.sh --stage FAILED_STAGE --force-stage
```

#### Lock File Issues
```bash
# Clean stale locks
./bootstrap.sh --reset-state

# Manual lock cleanup
sudo rm -f /var/run/bootstrap.lock
sudo rm -f /opt/bootstrap/stages/*.lock
```

### Debugging

#### Enable Debug Logging
```bash
# Check debug output in logs
tail -f /var/log/bootstrap-*.log | grep DEBUG
```

#### Manual Verification
```bash
# Check system state
systemctl status cockpit.socket
systemctl status chronyd
lsmod | grep kvm
```

### Recovery Procedures

#### Complete Recovery
```bash
# Reset and start fresh
sudo ./bootstrap.sh --reset-state
sudo ./bootstrap.sh --rollback
sudo ./bootstrap.sh
```

#### Partial Recovery
```bash
# Fix specific stage
sudo ./bootstrap.sh --stage FAILED_STAGE --force-stage
```

## 🛡️ Security

### Security Features

#### Password Management
- Minimum 8-character requirement
- Secure password input (hidden)
- Password confirmation in interactive mode
- Strength recommendations

#### User Security
- Root login blocked in Cockpit
- Group-based access control
- SSH key directory setup
- Sudo access configuration

#### Network Security
- Firewall configuration
- Secure default settings
- Port management
- Service hardening

### Security Best Practices

#### Password Security
```bash
# Use strong passwords
./bootstrap.sh -p 'MyStr0ng#P@ssw0rd!' -r 'R00t#Secure123!'

# Consider using password managers
# Change default passwords immediately
```

#### Network Security
```bash
# Use non-standard ports
./bootstrap.sh --cockpit-port 8443

# Restrict access by IP
# Use VPN for remote access
```

#### System Security
```bash
# Keep system updated
sudo dnf update -y

# Monitor logs regularly
sudo journalctl -f

# Review user access
sudo ./bootstrap.sh --show-state
```

## 🔧 System Requirements

### Minimum Requirements
- **OS**: AlmaLinux 9.0 or higher
- **RAM**: 2GB minimum (4GB recommended)
- **Storage**: 20GB free space
- **Network**: Internet connectivity for package downloads

### Recommended Requirements
- **OS**: AlmaLinux 9.2 or higher
- **RAM**: 4GB or more
- **Storage**: 50GB free space
- **Network**: Stable broadband connection

### Supported Architectures
- x86_64 (Intel/AMD 64-bit)
- aarch64 (ARM 64-bit)

## 📊 Monitoring & Logging

### Log Files

| File | Purpose |
|------|---------|
| `/var/log/bootstrap-*.log` | Main execution logs |
| `/opt/bootstrap/state` | Stage completion state |
| `/var/lib/bootstrap-status.json` | JSON status tracking |
| `/var/log/cockpit/` | Cockpit web interface logs |

### Monitoring Integration

#### Prometheus Metrics
```bash
# PCP metrics endpoint
curl http://localhost:44322/metrics
```

#### Log Aggregation
```bash
# Structured JSON logging
./bootstrap.sh --json-logging
```

### System Status

#### Health Check
```bash
# Quick system status
./bootstrap.sh --show-state
systemctl status cockpit.socket
systemctl status chronyd
```

## 🤝 Contributing

### Development Setup
```bash
git clone https://github.com/simhaonline/pro-scripts.git
cd almalinux-bootstrap
```

### Testing
```bash
# Test in VM environment
# Use --show-state for verification
# Test rollback functionality
```

### Submitting Issues
1. Check existing issues
2. Provide system information
3. Include log files
4. Describe expected vs actual behavior

### Pull Requests
1. Fork the repository
2. Create feature branch
3. Test thoroughly
4. Submit pull request

## 📄 License

This script is licensed for production use with attribution required.

**Author**: Simha.Online <admin@simhaonline.com>  
**Version**: 2025.07.04  
**License**: Production Use Allowed with Attribution

## 🆘 Support

### Community Support
- **GitHub Issues**: [Report bugs and request features](https://github.com/simhaonline/pro-scripts/issues)
- **Discussions**: [Community discussions](https://github.com/simhaonline/pro-scripts/discussions)

### Professional Support
- **Email**: admin@simhaonline.com
- **Website**: https://simhaonline.com

### Documentation
- **Wiki**: [Detailed documentation](https://github.com/simhaonline/pro-scripts/wiki)
- **FAQ**: [Frequently asked questions](https://github.com/simhaonline/pro-scripts/wiki/FAQ)

---

## 📈 Changelog

### Version 2025.07.04
- ✅ Added stage-based execution system
- ✅ Implemented rollback functionality
- ✅ Added configuration management
- ✅ Enhanced logging and monitoring
- ✅ Improved error handling
- ✅ Added JSON logging support
- ✅ Implemented lock management
- ✅ Added Cockpit web management
- ✅ Enhanced security features

### Previous Versions
See [CHANGELOG.md](CHANGELOG.md) for complete version history.

---

*This documentation is maintained by the AlmaLinux Bootstrap Script project contributors.*
