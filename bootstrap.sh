#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

###----------------------------------------------------
# Simha Cloud: AlmaLinux 9+ Production Bootstrap Script
# Author: Simha.Online <admin@simhaonline.com>
# License: Production Use Allowed with Attribution
# Version: 2025.07.04
# Description: Modular, production-grade bootstrap with rollback support
###----------------------------------------------------

# ==== SCRIPT CONFIGURATION ====
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_VERSION="2025.07.04"
readonly BACKUP_DIR="/var/backups/bootstrap-$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="/var/log/bootstrap-$(date +%Y%m%d_%H%M%S).log"
readonly LOCK_FILE="/var/run/bootstrap.lock"
readonly CONFIG_FILE="/etc/bootstrap-config.env"
readonly STATUS_FILE="/var/lib/bootstrap-status.json"
readonly LOGROTATE_FILE="/etc/logrotate.d/bootstrap"
readonly STATE_DIR="/opt/bootstrap"
readonly STATE_FILE="$STATE_DIR/state"
readonly STAGE_LOCK_DIR="$STATE_DIR/stages"

# ==== DEFAULT CONFIGURATION ====
SYSADMIN_USER="sysadmin"
SYSADMIN_PASS="5imhA#2025"
ROOT_PASS="M3hU!#2025"
HOSTNAME=""
NON_INTERACTIVE=false
JSON_LOGGING=false
ENABLE_SELINUX_CONFIG=true
ENABLE_USER_CREATION=true
ENABLE_HOSTNAME_CONFIG=true
ENABLE_DNF_TUNING=true
ENABLE_REPOS=true
ENABLE_SYSTEM_UPDATE=true
ENABLE_TOOLS_INSTALL=true
ENABLE_AUTO_UPDATES=true
ENABLE_TIME_SYNC=true
ENABLE_KERNEL_MODULES=true
ENABLE_COCKPIT_MANAGEMENT=true
ENABLE_ROLLBACK_SUPPORT=true
SKIP_REBOOT_PROMPT=false
STAGE_MODE=""
LOAD_CONFIG=false
RESET_STATE=false
SHOW_STATE=false
FORCE_STAGE=false

# Time synchronization configuration
CHRONY_SERVERS=(
    "0.pool.ntp.org"
    "1.pool.ntp.org"
    "2.pool.ntp.org"
    "3.pool.ntp.org"
)
GEOIP_SERVICE="http://ip-api.com/json/"
FALLBACK_TIMEZONE="UTC"

# Network configuration
PUBLIC_IPV4=""
PUBLIC_IPV6=""
CURRENT_HOSTNAME=""

# System hardware information
CPU_VENDOR=""
CPU_MODEL=""
VIRTUALIZATION_SUPPORT=""

# Cockpit configuration
COCKPIT_PORT=9090
PCP_EXPORT_PORT=44322
COCKPIT_GROUP="cockpit-admin"

# Stage definitions
STAGE_LIST=(
    "selinux"
    "hostname"
    "users"
    "dnf"
    "repos"
    "updates"
    "tools"
    "auto-updates"
    "time-sync"
    "kernel-modules"
    "cockpit"
)

# ==== LOGGING FUNCTIONS ====
log_json() {
    local level="$1"
    local msg="$2"
    local timestamp=$(date '+%Y-%m-%dT%H:%M:%S.%3NZ')
    
    if [[ "$JSON_LOGGING" == "true" ]]; then
        echo "{\"timestamp\":\"$timestamp\",\"level\":\"$level\",\"message\":\"$msg\",\"script\":\"$SCRIPT_NAME\",\"version\":\"$SCRIPT_VERSION\"}" | tee -a "$LOG_FILE"
    fi
}

log_info()    { 
    local msg="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[1;32m[INFO]\033[0m  $timestamp $msg" | tee -a "$LOG_FILE"
    log_json "INFO" "$msg"
}

log_warn()    { 
    local msg="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[1;33m[WARN]\033[0m  $timestamp $msg" | tee -a "$LOG_FILE"
    log_json "WARN" "$msg"
}

log_error()   { 
    local msg="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[1;31m[ERROR]\033[0m $timestamp $msg" | tee -a "$LOG_FILE"
    log_json "ERROR" "$msg"
}

log_success() { 
    local msg="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[1;32m[SUCCESS]\033[0m $timestamp $msg" | tee -a "$LOG_FILE"
    log_json "SUCCESS" "$msg"
}

log_debug()   { 
    local msg="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[1;36m[DEBUG]\033[0m $timestamp $msg" | tee -a "$LOG_FILE"
    log_json "DEBUG" "$msg"
}

# ==== UTILITY FUNCTIONS ====
show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Production-grade AlmaLinux 9+ bootstrap script with rollback support.

In interactive mode, you will be prompted for hostname, sysadmin and root passwords
unless provided via command line arguments.

The script intelligently handles existing users:
- If sysadmin user exists: Updates configuration, groups, and password
- If sysadmin user doesn't exist: Creates new user with full configuration
- Rollback preserves existing users and only removes script-created users

OPTIONS:
    -h, --help                  Show this help message
    -v, --version               Show script version
    -n, --non-interactive       Run in non-interactive mode
    -H, --hostname HOSTNAME     Set system hostname (FQDN recommended)
    -u, --sysadmin-user USER    Set sysadmin username (default: sysadmin)
    -p, --sysadmin-pass PASS    Set sysadmin password (prompts if not provided)
    -r, --root-pass PASS        Set root password (prompts if not provided)
    --load-config               Load configuration from $CONFIG_FILE
    --json-logging              Enable JSON formatted logging
    --stage MODULE              Run only specific stage (selinux,hostname,users,dnf,repos,updates,tools,auto-updates,time-sync,kernel-modules,cockpit)
    --force-stage               Force run stage even if already completed
    --reset-state               Reset all stage completion state
    --show-state                Show current stage completion state
    --skip-selinux              Skip SELinux configuration
    --skip-hostname             Skip hostname configuration
    --skip-users                Skip user creation/configuration
    --skip-dnf-tuning           Skip DNF configuration tuning
    --skip-repos                Skip repository configuration
    --skip-updates              Skip system updates
    --skip-tools                Skip tools installation
    --skip-auto-updates         Skip auto-updates configuration
    --skip-time-sync            Skip time synchronization and timezone setup
    --skip-kernel-modules       Skip kernel modules configuration
    --skip-cockpit              Skip Cockpit web management interface
    --skip-rollback             Skip rollback support setup
    --skip-reboot-prompt        Skip reboot prompt at end
    --rollback                  Perform rollback from backup
    --list-backups              List available backups

EXAMPLES:
    $SCRIPT_NAME                                    # Interactive mode with prompts
    $SCRIPT_NAME -n                                # Non-interactive mode (uses defaults)
    $SCRIPT_NAME --load-config                     # Load saved configuration
    $SCRIPT_NAME --json-logging                    # Enable JSON logging
    $SCRIPT_NAME --stage users                     # Run only user configuration
    $SCRIPT_NAME -H server.example.com             # Set hostname interactively
    $SCRIPT_NAME -n -H web01.domain.com            # Set hostname non-interactively
    $SCRIPT_NAME -u admin -p MyPass123             # Custom sysadmin user and password
    $SCRIPT_NAME -n --skip-updates                 # Skip system updates
    $SCRIPT_NAME --skip-hostname --skip-time-sync  # Skip hostname and time sync
    $SCRIPT_NAME --skip-kernel-modules             # Skip kernel modules loading
    $SCRIPT_NAME --skip-cockpit                    # Skip Cockpit web interface
    $SCRIPT_NAME --rollback                        # Perform rollback
    $SCRIPT_NAME --list-backups                    # List available backups

STAGE MODE:
    Use --stage to run only specific configuration modules:
    - selinux: SELinux configuration
    - hostname: Hostname and network configuration
    - users: User creation and management
    - dnf: DNF package manager tuning
    - repos: Repository configuration
    - updates: System updates
    - tools: Essential tools installation
    - auto-updates: Automatic updates configuration
    - time-sync: Time synchronization and timezone
    - kernel-modules: Kernel modules and optimization
    - cockpit: Cockpit web management interface

CONFIGURATION MANAGEMENT:
    - Configuration is automatically saved to $CONFIG_FILE
    - Use --load-config to reuse previous settings
    - Status tracking prevents duplicate operations
    - JSON logging available for automated systems

HOSTNAME CONFIGURATION:
    - Automatically detects public IPv4 and IPv6 addresses
    - Updates /etc/hostname, /etc/hosts, and systemd hostname
    - Supports both FQDN and short hostnames
    - Validates hostname format and length
    - Creates comprehensive hosts file with local and public IPs

KERNEL MODULES CONFIGURATION:
    - Automatically detects CPU vendor (Intel/AMD) and virtualization support
    - Loads appropriate KVM modules (kvm_intel or kvm_amd) with nested virtualization
    - Configures network optimization modules (tcp_bbr, br_netfilter, etc.)
    - Sets up container and overlay filesystem modules
    - Optimizes system performance with sysctl parameters
    - Supports both bare metal and virtualized environments

COCKPIT WEB MANAGEMENT:
    - Installs Cockpit web management interface on port 9090
    - Configures secure access with cockpit-admin group restrictions
    - Blocks root login for security
    - Enables PCP monitoring with Prometheus metrics on port 44322
    - Automatically adds sysadmin user to cockpit-admin group
    - Configures firewall rules for web access
    - Provides comprehensive system monitoring and management

USER MANAGEMENT:
    - Detects existing sysadmin users and updates configuration
    - Creates new users only if they don't exist
    - Updates groups, shell, sudo access, and home directory
    - Configures SSH directory and bash profile
    - Rollback intelligently handles pre-existing vs script-created users

SECURITY NOTES:
    - Passwords are validated for minimum 8 characters
    - Interactive mode provides secure password input (hidden)
    - Password confirmation is required in interactive mode
    - Strong password recommendations are provided
    - Existing user configurations are preserved during rollback
    - Cockpit access is restricted to authorized users only

EOF
}

show_version() {
    echo "$SCRIPT_NAME version $SCRIPT_VERSION"
}

# ==== CONFIGURATION MANAGEMENT ====
save_config() {
    log_info "Saving configuration to $CONFIG_FILE"
    
    cat > "$CONFIG_FILE" << EOF
# Bootstrap Configuration - Generated $(date)
SYSADMIN_USER="$SYSADMIN_USER"
HOSTNAME="$HOSTNAME"
NON_INTERACTIVE="$NON_INTERACTIVE"
JSON_LOGGING="$JSON_LOGGING"
ENABLE_SELINUX_CONFIG="$ENABLE_SELINUX_CONFIG"
ENABLE_USER_CREATION="$ENABLE_USER_CREATION"
ENABLE_HOSTNAME_CONFIG="$ENABLE_HOSTNAME_CONFIG"
ENABLE_DNF_TUNING="$ENABLE_DNF_TUNING"
ENABLE_REPOS="$ENABLE_REPOS"
ENABLE_SYSTEM_UPDATE="$ENABLE_SYSTEM_UPDATE"
ENABLE_TOOLS_INSTALL="$ENABLE_TOOLS_INSTALL"
ENABLE_AUTO_UPDATES="$ENABLE_AUTO_UPDATES"
ENABLE_TIME_SYNC="$ENABLE_TIME_SYNC"
ENABLE_KERNEL_MODULES="$ENABLE_KERNEL_MODULES"
ENABLE_COCKPIT_MANAGEMENT="$ENABLE_COCKPIT_MANAGEMENT"
ENABLE_ROLLBACK_SUPPORT="$ENABLE_ROLLBACK_SUPPORT"
SKIP_REBOOT_PROMPT="$SKIP_REBOOT_PROMPT"
COCKPIT_PORT="$COCKPIT_PORT"
PCP_EXPORT_PORT="$PCP_EXPORT_PORT"
COCKPIT_GROUP="$COCKPIT_GROUP"
FALLBACK_TIMEZONE="$FALLBACK_TIMEZONE"
EOF
    
    chmod 600 "$CONFIG_FILE"
    log_success "Configuration saved to $CONFIG_FILE"
}

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Loading configuration from $CONFIG_FILE"
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
        log_success "Configuration loaded successfully"
    else
        log_warn "Configuration file $CONFIG_FILE not found"
    fi
}

# ==== STATUS TRACKING ====
init_status_file() {
    mkdir -p "$(dirname "$STATUS_FILE")"
    if [[ ! -f "$STATUS_FILE" ]]; then
        echo '{"modules":{},"last_run":"","version":""}' > "$STATUS_FILE"
    fi
}

update_module_status() {
    local module="$1"
    local status="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Update status file using jq if available, otherwise simple replacement
    if command -v jq >/dev/null 2>&1; then
        jq --arg module "$module" --arg status "$status" --arg timestamp "$timestamp" \
           '.modules[$module] = {"status": $status, "timestamp": $timestamp}' \
           "$STATUS_FILE" > "${STATUS_FILE}.tmp" && mv "${STATUS_FILE}.tmp" "$STATUS_FILE"
    else
        # Fallback without jq
        log_debug "Module $module: $status at $timestamp"
    fi
}

check_module_status() {
    local module="$1"
    
    if [[ -f "$STATUS_FILE" ]] && command -v jq >/dev/null 2>&1; then
        local status=$(jq -r --arg module "$module" '.modules[$module].status // "not_run"' "$STATUS_FILE")
        echo "$status"
    else
        echo "not_run"
    fi
}

# ==== STAGE LOCKING & RESUMPTION ====
init_stage_system() {
    log_info "Initializing stage tracking system"
    
    # Create state directories
    mkdir -p "$STATE_DIR"
    mkdir -p "$STAGE_LOCK_DIR"
    
    # Create state file if it doesn't exist
    if [[ ! -f "$STATE_FILE" ]]; then
        cat > "$STATE_FILE" << EOF
# Bootstrap Stage State File
# Generated: $(date)
# Format: stage:status:timestamp
# Status: pending, running, completed, failed
EOF
        log_debug "Created state file: $STATE_FILE"
    fi
    
    # Set proper permissions
    chmod 755 "$STATE_DIR"
    chmod 644 "$STATE_FILE" 2>/dev/null || true
    chmod 755 "$STAGE_LOCK_DIR"
    
    log_debug "Stage tracking system initialized"
}

mark_stage_running() {
    local stage="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local lock_file="$STAGE_LOCK_DIR/$stage.lock"
    
    log_debug "Marking stage '$stage' as running"
    
    # Create lock file with PID and timestamp
    cat > "$lock_file" << EOF
PID=$
START_TIME=$timestamp
SCRIPT_VERSION=$SCRIPT_VERSION
EOF
    
    # Update state file
    if grep -q "^stage:$stage:" "$STATE_FILE" 2>/dev/null; then
        sed -i "s/^stage:$stage:.*/stage:$stage:running:$timestamp/" "$STATE_FILE"
    else
        echo "stage:$stage:running:$timestamp" >> "$STATE_FILE"
    fi
    
    log_json "STAGE_START" "Stage $stage started"
}

mark_stage_completed() {
    local stage="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local lock_file="$STAGE_LOCK_DIR/$stage.lock"
    
    log_debug "Marking stage '$stage' as completed"
    
    # Remove lock file
    rm -f "$lock_file"
    
    # Update state file
    if grep -q "^stage:$stage:" "$STATE_FILE" 2>/dev/null; then
        sed -i "s/^stage:$stage:.*/stage:$stage:completed:$timestamp/" "$STATE_FILE"
    else
        echo "stage:$stage:completed:$timestamp" >> "$STATE_FILE"
    fi
    
    log_json "STAGE_COMPLETE" "Stage $stage completed"
    log_success "Stage '$stage' completed successfully"
}

mark_stage_failed() {
    local stage="$1"
    local error_msg="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local lock_file="$STAGE_LOCK_DIR/$stage.lock"
    
    log_error "Stage '$stage' failed: $error_msg"
    
    # Update lock file with error
    if [[ -f "$lock_file" ]]; then
        echo "ERROR=$error_msg" >> "$lock_file"
        echo "FAIL_TIME=$timestamp" >> "$lock_file"
    fi
    
    # Update state file
    if grep -q "^stage:$stage:" "$STATE_FILE" 2>/dev/null; then
        sed -i "s/^stage:$stage:.*/stage:$stage:failed:$timestamp/" "$STATE_FILE"
    else
        echo "stage:$stage:failed:$timestamp" >> "$STATE_FILE"
    fi
    
    log_json "STAGE_FAILED" "Stage $stage failed: $error_msg"
}

is_stage_completed() {
    local stage="$1"
    
    if [[ -f "$STATE_FILE" ]]; then
        if grep -q "^stage:$stage:completed:" "$STATE_FILE" 2>/dev/null; then
            return 0  # Stage is completed
        fi
    fi
    
    return 1  # Stage is not completed
}

is_stage_running() {
    local stage="$1"
    local lock_file="$STAGE_LOCK_DIR/$stage.lock"
    
    if [[ -f "$lock_file" ]]; then
        # Check if the process is still running
        local pid=$(grep "^PID=" "$lock_file" | cut -d= -f2)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            return 0  # Stage is running
        else
            # Stale lock file, mark as failed
            mark_stage_failed "$stage" "Process terminated unexpectedly"
            return 1
        fi
    fi
    
    return 1  # Stage is not running
}

get_stage_status() {
    local stage="$1"
    
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "pending"
        return
    fi
    
    local status_line=$(grep "^stage:$stage:" "$STATE_FILE" 2>/dev/null | tail -1)
    if [[ -n "$status_line" ]]; then
        echo "$status_line" | cut -d: -f3
    else
        echo "pending"
    fi
}

get_stage_timestamp() {
    local stage="$1"
    
    if [[ ! -f "$STATE_FILE" ]]; then
        echo ""
        return
    fi
    
    local status_line=$(grep "^stage:$stage:" "$STATE_FILE" 2>/dev/null | tail -1)
    if [[ -n "$status_line" ]]; then
        echo "$status_line" | cut -d: -f4-
    else
        echo ""
    fi
}

show_stage_state() {
    log_info "Current stage completion state:"
    echo
    printf "%-15s %-12s %-20s\n" "STAGE" "STATUS" "TIMESTAMP"
    printf "%-15s %-12s %-20s\n" "$(printf '%0.s-' {1..15})" "$(printf '%0.s-' {1..12})" "$(printf '%0.s-' {1..20})"
    
    for stage in "${STAGE_LIST[@]}"; do
        local status=$(get_stage_status "$stage")
        local timestamp=$(get_stage_timestamp "$stage")
        
        # Color coding for status
        case "$status" in
            "completed")
                printf "%-15s \033[1;32m%-12s\033[0m %-20s\n" "$stage" "$status" "$timestamp"
                ;;
            "running")
                printf "%-15s \033[1;33m%-12s\033[0m %-20s\n" "$stage" "$status" "$timestamp"
                ;;
            "failed")
                printf "%-15s \033[1;31m%-12s\033[0m %-20s\n" "$stage" "$status" "$timestamp"
                ;;
            *)
                printf "%-15s %-12s %-20s\n" "$stage" "$status" "$timestamp"
                ;;
        esac
    done
    echo
    
    # Show summary
    local completed_count=0
    local failed_count=0
    local running_count=0
    local pending_count=0
    
    for stage in "${STAGE_LIST[@]}"; do
        local status=$(get_stage_status "$stage")
        case "$status" in
            "completed") ((completed_count++)) ;;
            "failed") ((failed_count++)) ;;
            "running") ((running_count++)) ;;
            *) ((pending_count++)) ;;
        esac
    done
    
    log_info "Summary: $completed_count completed, $running_count running, $failed_count failed, $pending_count pending"
    
    # Show next stage to run
    local next_stage=""
    for stage in "${STAGE_LIST[@]}"; do
        local status=$(get_stage_status "$stage")
        if [[ "$status" != "completed" ]]; then
            next_stage="$stage"
            break
        fi
    done
    
    if [[ -n "$next_stage" ]]; then
        log_info "Next stage to run: $next_stage"
    else
        log_info "All stages completed"
    fi
}

reset_stage_state() {
    log_info "Resetting all stage completion state"
    
    # Remove all lock files
    rm -f "$STAGE_LOCK_DIR"/*.lock 2>/dev/null || true
    
    # Reset state file
    cat > "$STATE_FILE" << EOF
# Bootstrap Stage State File
# Reset: $(date)
# Format: stage:status:timestamp
# Status: pending, running, completed, failed
EOF
    
    # Clean up status file
    if [[ -f "$STATUS_FILE" ]]; then
        if command -v jq >/dev/null 2>&1; then
            jq '.modules = {}' "$STATUS_FILE" > "${STATUS_FILE}.tmp" && mv "${STATUS_FILE}.tmp" "$STATUS_FILE"
        fi
    fi
    
    log_success "Stage state reset completed"
}

cleanup_stale_locks() {
    log_debug "Cleaning up stale stage locks"
    
    for lock_file in "$STAGE_LOCK_DIR"/*.lock; do
        if [[ -f "$lock_file" ]]; then
            local stage=$(basename "$lock_file" .lock)
            local pid=$(grep "^PID=" "$lock_file" 2>/dev/null | cut -d= -f2)
            
            if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
                log_warn "Found stale lock for stage '$stage' (PID $pid no longer exists)"
                mark_stage_failed "$stage" "Process terminated unexpectedly"
            fi
        fi
    done
}

# ==== STAGE EXECUTION WRAPPER ====
execute_stage() {
    local stage="$1"
    local stage_function="$2"
    local stage_description="$3"
    
    # Check if stage should be skipped
    if [[ "$FORCE_STAGE" == "false" ]] && is_stage_completed "$stage"; then
        log_info "Stage '$stage' already completed. Skipping..."
        log_info "  Use --force-stage to force re-execution"
        return 0
    fi
    
    # Check if stage is currently running
    if is_stage_running "$stage"; then
        log_error "Stage '$stage' is currently running in another process"
        log_error "  If this is incorrect, use --reset-state to clear locks"
        return 1
    fi
    
    log_info "Executing stage: $stage ($stage_description)"
    mark_stage_running "$stage"
    
    # Execute the stage function with error handling
    if eval "$stage_function"; then
        mark_stage_completed "$stage"
        return 0
    else
        local exit_code=$?
        mark_stage_failed "$stage" "Function returned exit code $exit_code"
        return $exit_code
    fi
}

# ==== LOG ROTATION SETUP ====
setup_log_rotation() {
    log_info "Setting up log rotation for bootstrap logs"
    
    cat > "$LOGROTATE_FILE" << EOF
/var/log/bootstrap-*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    postrotate
        # Clean up old log files older than 90 days
        find /var/log -name "bootstrap-*.log*" -mtime +90 -delete 2>/dev/null || true
    endscript
}

$CONFIG_FILE {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 600 root root
    copytruncate
}
EOF
    
    log_success "Log rotation configured"
}

# ==== FIREWALL MANAGEMENT ====
configure_firewall_port() {
    local port="$1"
    local protocol="${2:-tcp}"
    local description="$3"
    
    # Check if firewalld is installed and running
    if command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active --quiet firewalld; then
            if ! firewall-cmd --zone=public --query-port="${port}/${protocol}" &>/dev/null; then
                log_info "Opening ${description} port ${port}/${protocol}"
                firewall-cmd --zone=public --add-port="${port}/${protocol}" --permanent || true
                firewall-cmd --reload || true
                log_success "${description} port ${port}/${protocol} opened"
            else
                log_info "${description} port ${port}/${protocol} already open"
            fi
        else
            log_warn "firewalld service is not running - cannot configure ${description} port ${port}/${protocol}"
        fi
    elif command -v ufw >/dev/null 2>&1; then
        # UFW fallback
        log_info "Using UFW to open ${description} port ${port}/${protocol}"
        ufw allow "${port}/${protocol}" || true
    elif command -v iptables >/dev/null 2>&1; then
        # iptables fallback
        log_info "Using iptables to open ${description} port ${port}/${protocol}"
        iptables -A INPUT -p "${protocol}" --dport "${port}" -j ACCEPT || true
        # Try to save rules
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    else
        log_warn "No firewall management tools found - manual configuration required for ${description} port ${port}/${protocol}"
    fi
}

# ==== IMPROVED GROUP MANAGEMENT ====
create_group_safe() {
    local group="$1"
    local description="$2"
    
    if ! getent group "$group" >/dev/null 2>&1; then
        log_info "Creating group: $group"
        if groupadd "$group" 2>/dev/null; then
            log_success "Group '$group' created successfully"
        else
            log_error "Failed to create group '$group'"
            return 1
        fi
    else
        log_info "Group '$group' already exists"
    fi
    
    return 0
}

# ==== IMPROVED PASSWORD HANDLING ====
set_user_password_safe() {
    local username="$1"
    local password="$2"
    
    if [[ -z "$username" || -z "$password" ]]; then
        log_error "Username and password cannot be empty"
        return 1
    fi
    
    # Use chpasswd with proper error handling
    if echo "$username:$password" | chpasswd 2>/dev/null; then
        log_success "Password set for user '$username'"
        
        # Verify password was set correctly
        if passwd -S "$username" 2>/dev/null | grep -q "P"; then
            log_debug "Password verification successful for '$username'"
        else
            log_warn "Password verification failed for '$username'"
        fi
    else
        log_error "Failed to set password for user '$username'"
        return 1
    fi
    
    return 0
}

# ==== PASSWORD MANAGEMENT ====
validate_password_strength() {
    local password="$1"
    local password_name="$2"
    
    # Check minimum length
    if [[ ${#password} -lt 8 ]]; then
        log_error "$password_name must be at least 8 characters long"
        return 1
    fi
    
    # Check for at least one uppercase letter
    if [[ ! "$password" =~ [A-Z] ]]; then
        log_warn "$password_name should contain at least one uppercase letter"
    fi
    
    # Check for at least one lowercase letter
    if [[ ! "$password" =~ [a-z] ]]; then
        log_warn "$password_name should contain at least one lowercase letter"
    fi
    
    # Check for at least one digit
    if [[ ! "$password" =~ [0-9] ]]; then
        log_warn "$password_name should contain at least one digit"
    fi
    
    # Check for at least one special character
    if [[ ! "$password" =~ [^a-zA-Z0-9] ]]; then
        log_warn "$password_name should contain at least one special character"
    fi
    
    return 0
}

prompt_for_password() {
    local password_name="$1"
    local default_password="$2"
    local password=""
    local password_confirm=""
    local attempts=0
    local max_attempts=3
    
    while [[ $attempts -lt $max_attempts ]]; do
        echo
        log_info "Setting up $password_name password"
        
        # Show default password option
        if [[ -n "$default_password" ]]; then
            echo "  Current default: $default_password"
            echo "  Press Enter to use default, or type new password:"
        else
            echo "  Enter new password:"
        fi
        
        # Read password securely
        echo -n "  Password: "
        read -s password
        echo
        
        # Use default if empty
        if [[ -z "$password" && -n "$default_password" ]]; then
            password="$default_password"
            log_info "Using default password for $password_name"
            break
        fi
        
        # Validate password strength
        if ! validate_password_strength "$password" "$password_name"; then
            ((attempts++))
            if [[ $attempts -lt $max_attempts ]]; then
                log_warn "Please try again. Attempt $((attempts + 1)) of $max_attempts"
                continue
            else
                log_error "Maximum attempts reached. Using default password."
                password="$default_password"
                break
            fi
        fi
        
        # Confirm password
        echo -n "  Confirm password: "
        read -s password_confirm
        echo
        
        if [[ "$password" == "$password_confirm" ]]; then
            log_success "$password_name password set successfully"
            break
        else
            log_error "Passwords do not match"
            ((attempts++))
            if [[ $attempts -lt $max_attempts ]]; then
                log_warn "Please try again. Attempt $((attempts + 1)) of $max_attempts"
            else
                log_error "Maximum attempts reached. Using default password."
                password="$default_password"
                break
            fi
        fi
    done
    
    echo "$password"
}

prompt_for_credentials() {
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        log_info "Non-interactive mode: Using provided or default credentials"
        return 0
    fi
    
    if [[ "$ENABLE_USER_CREATION" == "false" && "$ENABLE_HOSTNAME_CONFIG" == "false" ]]; then
        log_info "User creation and hostname configuration disabled: Skipping credential prompts"
        return 0
    fi
    
    log_info "Interactive configuration setup"
    echo
    echo "========================================="
    echo "  SYSTEM CONFIGURATION"
    echo "========================================="
    echo
    
    # Prompt for hostname configuration
    if [[ "$ENABLE_HOSTNAME_CONFIG" == "true" && -z "$HOSTNAME" ]]; then
        CURRENT_HOSTNAME=$(hostname 2>/dev/null || echo "localhost")
        echo "Current hostname: $CURRENT_HOSTNAME"
        echo "Enter new hostname (FQDN recommended, e.g., server.example.com):"
        echo -n "Hostname: "
        read -r new_hostname
        
        if [[ -n "$new_hostname" ]]; then
            if validate_hostname "$new_hostname"; then
                HOSTNAME="$new_hostname"
                log_info "Hostname set to: $HOSTNAME"
            else
                log_error "Invalid hostname format. Keeping current hostname."
                HOSTNAME="$CURRENT_HOSTNAME"
            fi
        else
            log_info "No hostname provided. Keeping current hostname: $CURRENT_HOSTNAME"
            HOSTNAME="$CURRENT_HOSTNAME"
        fi
    fi
    
    # Prompt for sysadmin username
    if [[ "$ENABLE_USER_CREATION" == "true" ]]; then
        echo
        echo "Current sysadmin username: $SYSADMIN_USER"
        echo -n "Enter new sysadmin username (or press Enter to keep current): "
        read -r new_username
        if [[ -n "$new_username" ]]; then
            SYSADMIN_USER="$new_username"
            log_info "Sysadmin username set to: $SYSADMIN_USER"
        fi
        
        # Prompt for sysadmin password if not provided via command line
        if [[ -z "${SYSADMIN_PASS_PROVIDED:-}" ]]; then
            SYSADMIN_PASS=$(prompt_for_password "sysadmin ($SYSADMIN_USER)" "$SYSADMIN_PASS")
        else
            log_info "Using sysadmin password provided via command line"
        fi
        
        # Prompt for root password if not provided via command line
        if [[ -z "${ROOT_PASS_PROVIDED:-}" ]]; then
            ROOT_PASS=$(prompt_for_password "root" "$ROOT_PASS")
        else
            log_info "Using root password provided via command line"
        fi
    fi
    
    echo
    echo "========================================="
    echo "  CONFIGURATION SETUP COMPLETE"
    echo "========================================="
    echo
    
    # Final validation
    if [[ "$ENABLE_USER_CREATION" == "true" ]]; then
        validate_passwords
    fi
}

# ==== HOSTNAME MANAGEMENT ====
validate_hostname() {
    local hostname="$1"
    
    # Check if hostname is empty
    if [[ -z "$hostname" ]]; then
        log_error "Hostname cannot be empty"
        return 1
    fi
    
    # Check hostname length (max 253 characters)
    if [[ ${#hostname} -gt 253 ]]; then
        log_error "Hostname is too long (max 253 characters)"
        return 1
    fi
    
    # Check for valid characters (alphanumeric, hyphens, dots)
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        log_error "Hostname contains invalid characters (only alphanumeric, hyphens, and dots allowed)"
        return 1
    fi
    
    # Check that hostname doesn't start or end with hyphen or dot
    if [[ "$hostname" =~ ^[-.]|[-.]$ ]]; then
        log_error "Hostname cannot start or end with hyphen or dot"
        return 1
    fi
    
    # Check for consecutive dots
    if [[ "$hostname" =~ \.\. ]]; then
        log_error "Hostname cannot contain consecutive dots"
        return 1
    fi
    
    # Check each label (part separated by dots)
    IFS='.' read -ra LABELS <<< "$hostname"
    for label in "${LABELS[@]}"; do
        if [[ ${#label} -gt 63 ]]; then
            log_error "Hostname label '$label' is too long (max 63 characters)"
            return 1
        fi
        if [[ "$label" =~ ^-|-$ ]]; then
            log_error "Hostname label '$label' cannot start or end with hyphen"
            return 1
        fi
    done
    
    return 0
}

detect_public_ips() {
    log_info "Detecting public IPv4 and IPv6 addresses"
    
    # Detect public IPv4
    local ipv4_services=(
        "https://ipv4.icanhazip.com"
        "https://ipinfo.io/ip"
        "https://api.ipify.org"
        "https://checkip.amazonaws.com"
    )
    
    for service in "${ipv4_services[@]}"; do
        log_debug "Trying IPv4 service: $service"
        PUBLIC_IPV4=$(curl -s --max-time 10 "$service" 2>/dev/null | tr -d '\n\r' || echo "")
        
        # Validate IPv4 format
        if [[ "$PUBLIC_IPV4" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            log_success "Public IPv4 detected: $PUBLIC_IPV4"
            break
        else
            log_debug "Service $service returned invalid IPv4: $PUBLIC_IPV4"
            PUBLIC_IPV4=""
        fi
    done
    
    # Detect public IPv6
    local ipv6_services=(
        "https://ipv6.icanhazip.com"
        "https://api6.ipify.org"
        "https://ipv6.ident.me"
    )
    
    for service in "${ipv6_services[@]}"; do
        log_debug "Trying IPv6 service: $service"
        PUBLIC_IPV6=$(curl -s --max-time 10 "$service" 2>/dev/null | tr -d '\n\r' || echo "")
        
        # Basic IPv6 validation (contains colons and valid characters)
        if [[ "$PUBLIC_IPV6" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$PUBLIC_IPV6" =~ : ]]; then
            log_success "Public IPv6 detected: $PUBLIC_IPV6"
            break
        else
            log_debug "Service $service returned invalid IPv6: $PUBLIC_IPV6"
            PUBLIC_IPV6=""
        fi
    done
    
    # Log results
    if [[ -z "$PUBLIC_IPV4" ]]; then
        log_warn "Could not detect public IPv4 address"
    fi
    
    if [[ -z "$PUBLIC_IPV6" ]]; then
        log_warn "Could not detect public IPv6 address"
    fi
}

configure_hostname() {
    if [[ "$ENABLE_HOSTNAME_CONFIG" == "false" ]]; then
        log_info "Skipping hostname configuration"
        return 0
    fi
    
    log_info "Configuring system hostname and hosts file"
    
    # Use current hostname if none provided
    if [[ -z "$HOSTNAME" ]]; then
        HOSTNAME=$(hostname 2>/dev/null || echo "localhost")
        log_info "No hostname provided, using current: $HOSTNAME"
    fi
    
    # Backup current configuration
    backup_file "/etc/hostname" "hostname"
    backup_file "/etc/hosts" "hosts"
    
    # Set hostname using improved method
    log_info "Setting hostname to: $HOSTNAME"
    
    # Method 1: Update /etc/hostname
    echo "$HOSTNAME" > /etc/hostname
    
    # Method 2: Use hostnamectl with single call (improved)
    if command -v hostnamectl >/dev/null 2>&1; then
        hostnamectl set-hostname --static "$HOSTNAME" || true
        systemctl restart systemd-hostnamed || true
        log_debug "Hostname set using hostnamectl"
    fi
    
    # Method 3: Use hostname command as fallback
    hostname "$HOSTNAME" 2>/dev/null || true
    
    # Detect public IP addresses
    detect_public_ips
    
    # Update /etc/hosts file
    log_info "Updating /etc/hosts file"
    
    # Extract short hostname (first part before first dot)
    local short_hostname="${HOSTNAME%%.*}"
    
    # Create new hosts file
    cat > /etc/hosts << EOF
# This file is managed by AlmaLinux Bootstrap Script
# Last updated: $(date)

# Local IPv4
127.0.0.1 localhost.localdomain localhost
127.0.0.1 $HOSTNAME $short_hostname

EOF
    
    # Add public IPv4 if detected
    if [[ -n "$PUBLIC_IPV4" ]]; then
        cat >> /etc/hosts << EOF
# Public IPv4
$PUBLIC_IPV4 $HOSTNAME $short_hostname

EOF
        log_info "Added public IPv4 to hosts file: $PUBLIC_IPV4"
    fi
    
    # Add IPv6 entries
    cat >> /etc/hosts << EOF
# Local IPv6
::1     localhost localhost.localdomain localhost6 localhost6.localdomain6 ip6-localhost ip6-loopback
::1     $HOSTNAME $short_hostname
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

EOF
    
    # Add public IPv6 if detected
    if [[ -n "$PUBLIC_IPV6" ]]; then
        cat >> /etc/hosts << EOF
# Public IPv6
$PUBLIC_IPV6 $HOSTNAME $short_hostname
EOF
        log_info "Added public IPv6 to hosts file: $PUBLIC_IPV6"
    fi
    
    # Verify hostname configuration
    sleep 1
    local current_hostname=$(hostname 2>/dev/null || echo "unknown")
    if [[ "$current_hostname" == "$HOSTNAME" ]]; then
        log_success "Hostname successfully configured: $HOSTNAME"
    else
        log_warn "Hostname verification failed. Expected: $HOSTNAME, Got: $current_hostname"
    fi
    
    # Show hostname status
    if command -v hostnamectl >/dev/null 2>&1; then
        log_info "Hostname status:"
        hostnamectl status || true
    fi
    
    # Display network configuration summary
    log_info "Network configuration summary:"
    log_info "  Hostname: $HOSTNAME"
    log_info "  Short name: $short_hostname"
    [[ -n "$PUBLIC_IPV4" ]] && log_info "  Public IPv4: $PUBLIC_IPV4"
    [[ -n "$PUBLIC_IPV6" ]] && log_info "  Public IPv6: $PUBLIC_IPV6"
    
    update_module_status "hostname" "completed"
    log_success "Hostname and hosts file configuration completed"
}

# ==== BACKUP AND ROLLBACK FUNCTIONS ====
create_backup_directory() {
    log_info "Creating backup directory: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
}

backup_file() {
    local file="$1"
    local backup_name="${2:-$(basename "$file")}"
    
    if [[ -f "$file" ]]; then
        log_debug "Backing up $file to $BACKUP_DIR/$backup_name"
        cp "$file" "$BACKUP_DIR/$backup_name"
    else
        log_debug "File $file does not exist, skipping backup"
    fi
}

backup_directory() {
    local dir="$1"
    local backup_name="${2:-$(basename "$dir")}"
    
    if [[ -d "$dir" ]]; then
        log_debug "Backing up directory $dir to $BACKUP_DIR/$backup_name"
        cp -r "$dir" "$BACKUP_DIR/$backup_name"
    else
        log_debug "Directory $dir does not exist, skipping backup"
    fi
}

create_rollback_script() {
    log_info "Creating rollback script"
    
    # Create a user info file for rollback reference
    local user_info_file="$BACKUP_DIR/user_info.txt"
    cat > "$user_info_file" << EOF
# User information at time of script execution
SYSADMIN_USER=$SYSADMIN_USER
USER_EXISTED_BEFORE=$(id "$SYSADMIN_USER" &>/dev/null && echo "true" || echo "false")
SCRIPT_EXECUTION_TIME=$(date '+%Y-%m-%d %H:%M:%S')
EOF
    
    cat > "$BACKUP_DIR/rollback.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

BACKUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/bootstrap-rollback-$(date +%Y%m%d_%H%M%S).log"

log_info() { echo -e "\033[1;32m[INFO]\033[0m  $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "\033[1;31m[ERROR]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "\033[1;33m[WARN]\033[0m  $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"; }

if [[ "$EUID" -ne 0 ]]; then
    log_error "Rollback script must be run as root."
    exit 1
fi

log_info "Starting rollback process from $BACKUP_DIR"

# Load user information
if [[ -f "$BACKUP_DIR/user_info.txt" ]]; then
    source "$BACKUP_DIR/user_info.txt"
    log_info "Loaded user information: USER=$SYSADMIN_USER, EXISTED_BEFORE=$USER_EXISTED_BEFORE"
else
    log_warn "No user information found - using defaults"
    SYSADMIN_USER="sysadmin"
    USER_EXISTED_BEFORE="false"
fi

# Restore system files
for file in dnf.conf selinux_config sudoers chrony.conf hostname hosts cockpit_pam cockpit_disallowed_users; do
    if [[ -f "$BACKUP_DIR/$file" ]]; then
        case "$file" in
            dnf.conf) cp "$BACKUP_DIR/$file" /etc/dnf/dnf.conf ;;
            selinux_config) cp "$BACKUP_DIR/$file" /etc/selinux/config ;;
            sudoers) cp "$BACKUP_DIR/$file" /etc/sudoers ;;
            chrony.conf) cp "$BACKUP_DIR/$file" /etc/chrony.conf ;;
            hostname) cp "$BACKUP_DIR/$file" /etc/hostname ;;
            hosts) cp "$BACKUP_DIR/$file" /etc/hosts ;;
            cockpit_pam) cp "$BACKUP_DIR/$file" /etc/pam.d/cockpit ;;
            cockpit_disallowed_users) cp "$BACKUP_DIR/$file" /etc/cockpit/disallowed-users ;;
        esac
        log_info "Restored $file"
    fi
done

# Restore kernel modules configuration
if [[ -d "$BACKUP_DIR/modules-load.d" ]]; then
    log_info "Restoring kernel modules configuration"
    rm -rf /etc/modules-load.d/*
    cp -r "$BACKUP_DIR/modules-load.d"/* /etc/modules-load.d/ 2>/dev/null || true
    log_info "Restored /etc/modules-load.d/"
fi

if [[ -d "$BACKUP_DIR/modprobe.d" ]]; then
    rm -rf /etc/modprobe.d/*
    cp -r "$BACKUP_DIR/modprobe.d"/* /etc/modprobe.d/ 2>/dev/null || true
    log_info "Restored /etc/modprobe.d/"
fi

# Restore Cockpit socket configuration
if [[ -d "$BACKUP_DIR/cockpit_socket_d" ]]; then
    log_info "Restoring Cockpit socket configuration"
    rm -rf /etc/systemd/system/cockpit.socket.d/*
    cp -r "$BACKUP_DIR/cockpit_socket_d"/* /etc/systemd/system/cockpit.socket.d/ 2>/dev/null || true
    log_info "Restored Cockpit socket configuration"
fi

# Remove custom configurations
if [[ -f "/etc/sysctl.d/99-network-optimization.conf" ]]; then
    rm -f /etc/sysctl.d/99-network-optimization.conf
    log_info "Removed custom sysctl configuration"
fi

if [[ -f "/etc/cockpit/cockpit.conf" ]]; then
    rm -f /etc/cockpit/cockpit.conf
    log_info "Removed custom Cockpit configuration"
fi

if [[ -f "/etc/logrotate.d/cockpit" ]]; then
    rm -f /etc/logrotate.d/cockpit
    log_info "Removed custom Cockpit logrotate configuration"
fi

# Remove cockpit-admin group if it was created by the script
if getent group cockpit-admin &>/dev/null; then
    groupdel cockpit-admin 2>/dev/null || true
    log_info "Removed cockpit-admin group"
fi

# Restore user-related files if they exist
for file in passwd group shadow; do
    if [[ -f "$BACKUP_DIR/$file" ]]; then
        case "$file" in
            passwd) cp "$BACKUP_DIR/$file" /etc/passwd ;;
            group) cp "$BACKUP_DIR/$file" /etc/group ;;
            shadow) cp "$BACKUP_DIR/$file" /etc/shadow ;;
        esac
        log_info "Restored $file"
    fi
done

# Handle user rollback based on whether user existed before
if [[ "$USER_EXISTED_BEFORE" == "false" ]]; then
    # User was created by the script - remove it
    if id "$SYSADMIN_USER" &>/dev/null; then
        log_info "Removing user '$SYSADMIN_USER' (was created by bootstrap script)"
        userdel -r "$SYSADMIN_USER" 2>/dev/null || true
        log_info "User '$SYSADMIN_USER' removed"
    fi
    
    # Remove sysadmin group if it was created by the script
    if getent group sysadmin &>/dev/null; then
        groupdel sysadmin 2>/dev/null || true
        log_info "Group 'sysadmin' removed"
    fi
else
    # User existed before - restore from backup files
    log_info "User '$SYSADMIN_USER' existed before bootstrap - restored from backup files"
    log_warn "You may need to manually verify user configuration and password"
fi

# Restore timezone if backup exists
if [[ -f "$BACKUP_DIR/timezone" ]]; then
    cp "$BACKUP_DIR/timezone" /etc/timezone
    log_info "Restored timezone configuration"
fi

# Restore /etc/localtime if backup exists
if [[ -f "$BACKUP_DIR/localtime" ]]; then
    cp "$BACKUP_DIR/localtime" /etc/localtime
    log_info "Restored localtime configuration"
fi

# Restore hostname using systemd if available
if [[ -f "$BACKUP_DIR/hostname" ]] && command -v hostnamectl >/dev/null 2>&1; then
    local old_hostname=$(cat "$BACKUP_DIR/hostname")
    hostnamectl set-hostname --static "$old_hostname" 2>/dev/null || true
    hostnamectl set-hostname --pretty "$old_hostname" 2>/dev/null || true
    hostnamectl set-hostname --transient "$old_hostname" 2>/dev/null || true
    systemctl restart systemd-hostnamed 2>/dev/null || true
    log_info "Restored hostname: $old_hostname"
fi

# Restart services that may have been affected
systemctl restart chronyd 2>/dev/null || true
systemctl restart dnf-automatic.timer 2>/dev/null || true
systemctl restart systemd-hostnamed 2>/dev/null || true
systemctl restart systemd-modules-load.service 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true

# Stop and disable Cockpit services if they were enabled
systemctl disable --now cockpit.socket 2>/dev/null || true
systemctl disable --now pmcd 2>/dev/null || true
systemctl disable --now pmproxy 2>/dev/null || true

# Reload sysctl settings
sysctl --system 2>/dev/null || true

log_success "Rollback completed successfully!"
log_info "Review logs at $LOG_FILE"
log_info "Note: System configuration (hostname, passwords, network) was restored"
log_info "If user '$SYSADMIN_USER' existed before bootstrap, verify its configuration manually"
EOF
    chmod +x "$BACKUP_DIR/rollback.sh"
    log_success "Rollback script created at $BACKUP_DIR/rollback.sh"
}

list_backups() {
    echo "Available backups:"
    find /var/backups -name "bootstrap-*" -type d 2>/dev/null | sort -r | head -10
}

perform_rollback() {
    local backup_path="$1"
    
    if [[ ! -d "$backup_path" ]]; then
        log_error "Backup directory $backup_path does not exist"
        exit 1
    fi
    
    if [[ -f "$backup_path/rollback.sh" ]]; then
        log_info "Executing rollback from $backup_path"
        bash "$backup_path/rollback.sh"
    else
        log_error "No rollback script found in $backup_path"
        exit 1
    fi
}

# ==== LOCK MANAGEMENT ====
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid=$(cat "$LOCK_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log_error "Another instance is already running (PID: $pid)"
            exit 1
        else
            log_warn "Removing stale lock file"
            rm -f "$LOCK_FILE"
        fi
    fi
    
    echo $$ > "$LOCK_FILE"
    trap cleanup_lock EXIT
}

cleanup_lock() {
    rm -f "$LOCK_FILE"
}

# ==== VALIDATION FUNCTIONS ====
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        log_error "This script must be run as root."
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS version"
        exit 1
    fi
    
    source /etc/os-release
    
    if [[ "$ID" != "almalinux" ]]; then
        log_error "This script is designed for AlmaLinux only. Detected: $ID"
        exit 1
    fi
    
    local major_version=$(echo "$VERSION_ID" | cut -d. -f1)
    if [[ "$major_version" -lt 9 ]]; then
        log_error "This script requires AlmaLinux 9 or higher. Detected: $VERSION_ID"
        exit 1
    fi
    
    log_info "OS validation passed: $PRETTY_NAME"
}

validate_passwords() {
    if [[ ${#ROOT_PASS} -lt 8 ]]; then
        log_error "Root password must be at least 8 characters long"
        exit 1
    fi
    
    if [[ ${#SYSADMIN_PASS} -lt 8 ]]; then
        log_error "Sysadmin password must be at least 8 characters long"
        exit 1
    fi
    
    log_debug "Password validation passed"
}

# ==== MAIN CONFIGURATION MODULES ====
configure_selinux() {
    if [[ "$ENABLE_SELINUX_CONFIG" == "false" ]]; then
        log_info "Skipping SELinux configuration"
        return 0
    fi
    
    log_info "Configuring SELinux to permissive mode"
    
    # Backup current config
    backup_file "/etc/selinux/config" "selinux_config"
    
    # Set to permissive
    setenforce 0 2>/dev/null || true
    sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
    
    log_success "SELinux configured to permissive mode"
}

create_users() {
    if [[ "$ENABLE_USER_CREATION" == "false" ]]; then
        log_info "Skipping user creation"
        return 0
    fi
    
    log_info "Configuring users and setting passwords"
    
    # Backup sudoers and related files
    backup_file "/etc/sudoers" "sudoers"
    backup_file "/etc/passwd" "passwd"
    backup_file "/etc/group" "group"
    backup_file "/etc/shadow" "shadow"
    
    # Set root password using improved method
    log_info "Setting root password"
    if ! set_user_password_safe "root" "$ROOT_PASS"; then
        log_error "Failed to set root password"
        return 1
    fi
    
    # Check if sysadmin user already exists
    local user_exists=false
    local user_needs_update=false
    
    if id "$SYSADMIN_USER" &>/dev/null; then
        user_exists=true
        log_info "User '$SYSADMIN_USER' already exists - checking configuration"
        
        # Check current user configuration
        local current_groups=$(groups "$SYSADMIN_USER" 2>/dev/null | cut -d: -f2 | tr ' ' '\n' | sort | tr '\n' ' ')
        local current_shell=$(getent passwd "$SYSADMIN_USER" | cut -d: -f7)
        local current_home=$(getent passwd "$SYSADMIN_USER" | cut -d: -f6)
        
        log_debug "Current user info for '$SYSADMIN_USER':"
        log_debug "  Groups: $current_groups"
        log_debug "  Shell: $current_shell"
        log_debug "  Home: $current_home"
        
        # Check if user needs configuration updates
        if [[ "$current_groups" != *"sysadmin"* ]] || [[ "$current_groups" != *"wheel"* ]]; then
            user_needs_update=true
            log_info "User '$SYSADMIN_USER' needs group membership updates"
        fi
        
        if [[ "$current_shell" != "/bin/bash" ]]; then
            user_needs_update=true
            log_info "User '$SYSADMIN_USER' needs shell update"
        fi
        
        if [[ ! -d "$current_home" ]]; then
            user_needs_update=true
            log_info "User '$SYSADMIN_USER' home directory needs creation"
        fi
    else
        log_info "User '$SYSADMIN_USER' does not exist - will create new user"
    fi
    
    # Create or ensure sysadmin group exists using improved method
    if ! create_group_safe "sysadmin" "System administrators group"; then
        log_error "Failed to create sysadmin group"
        return 1
    fi
    
    # Create new user or update existing user
    if [[ "$user_exists" == "false" ]]; then
        log_info "Creating new user '$SYSADMIN_USER'"
        useradd -m -s /bin/bash -c "System Administrator" -g sysadmin -G users,wheel "$SYSADMIN_USER"
        log_success "User '$SYSADMIN_USER' created successfully"
    else
        log_info "Updating existing user '$SYSADMIN_USER'"
        
        # Update user groups
        log_info "Updating group memberships for '$SYSADMIN_USER'"
        usermod -g sysadmin "$SYSADMIN_USER"
        usermod -aG users,wheel "$SYSADMIN_USER"
        
        # Update shell if needed
        if [[ "$(getent passwd "$SYSADMIN_USER" | cut -d: -f7)" != "/bin/bash" ]]; then
            log_info "Updating shell to /bin/bash for '$SYSADMIN_USER'"
            usermod -s /bin/bash "$SYSADMIN_USER"
        fi
        
        # Update comment field
        usermod -c "System Administrator" "$SYSADMIN_USER"
        
        # Ensure home directory exists
        local user_home=$(getent passwd "$SYSADMIN_USER" | cut -d: -f6)
        if [[ ! -d "$user_home" ]]; then
            log_info "Creating home directory for '$SYSADMIN_USER'"
            mkdir -p "$user_home"
            chown "$SYSADMIN_USER:sysadmin" "$user_home"
            chmod 755 "$user_home"
            
            # Copy skeleton files
            if [[ -d "/etc/skel" ]]; then
                cp -r /etc/skel/. "$user_home/" 2>/dev/null || true
                chown -R "$SYSADMIN_USER:sysadmin" "$user_home"
            fi
        fi
        
        log_success "User '$SYSADMIN_USER' updated successfully"
    fi
    
    # Set password for sysadmin user using improved method
    log_info "Setting password for '$SYSADMIN_USER'"
    if ! set_user_password_safe "$SYSADMIN_USER" "$SYSADMIN_PASS"; then
        log_error "Failed to set password for '$SYSADMIN_USER'"
        return 1
    fi
    
    # Configure sudo access
    log_info "Configuring sudo access for sysadmin group"
    
    # Check if sudoers rule already exists
    if ! grep -q "^%sysadmin" /etc/sudoers; then
        log_info "Adding sysadmin group to sudoers"
        echo '%sysadmin ALL=(ALL) ALL' >> /etc/sudoers
    else
        log_debug "Sysadmin group already has sudo access"
    fi
    
    # Verify sudoers file syntax
    if ! visudo -c &>/dev/null; then
        log_error "Sudoers file syntax error detected - restoring backup"
        if [[ -f "$BACKUP_DIR/sudoers" ]]; then
            cp "$BACKUP_DIR/sudoers" /etc/sudoers
            log_info "Sudoers file restored from backup"
        fi
    else
        log_debug "Sudoers file syntax is valid"
    fi
    
    # Enable linger for systemd user services
    log_info "Enabling systemd user services for '$SYSADMIN_USER'"
    loginctl enable-linger "$SYSADMIN_USER" 2>/dev/null || true
    
    # Verify final user configuration
    log_info "Verifying user configuration"
    if id "$SYSADMIN_USER" &>/dev/null; then
        local final_groups=$(groups "$SYSADMIN_USER" 2>/dev/null | cut -d: -f2)
        local final_shell=$(getent passwd "$SYSADMIN_USER" | cut -d: -f7)
        local final_home=$(getent passwd "$SYSADMIN_USER" | cut -d: -f6)
        
        log_info "Final configuration for '$SYSADMIN_USER':"
        log_info "  Groups: $final_groups"
        log_info "  Shell: $final_shell"
        log_info "  Home: $final_home"
        
        # Test sudo access
        if sudo -l -U "$SYSADMIN_USER" &>/dev/null; then
            log_success "Sudo access verified for '$SYSADMIN_USER'"
        else
            log_warn "Sudo access verification failed for '$SYSADMIN_USER'"
        fi
        
        # Check if user can login (account not locked)
        if passwd -S "$SYSADMIN_USER" | grep -q "P"; then
            log_success "User '$SYSADMIN_USER' account is active and ready"
        else
            log_warn "User '$SYSADMIN_USER' account may be locked"
        fi
    else
        log_error "User verification failed - '$SYSADMIN_USER' not found"
        return 1
    fi
    
    # Set up SSH directory if it doesn't exist
    local ssh_dir="/home/$SYSADMIN_USER/.ssh"
    if [[ ! -d "$ssh_dir" ]]; then
        log_info "Creating SSH directory for '$SYSADMIN_USER'"
        mkdir -p "$ssh_dir"
        chown "$SYSADMIN_USER:sysadmin" "$ssh_dir"
        chmod 700 "$ssh_dir"
    fi
    
    # Configure bash profile for better experience
    local bash_profile="/home/$SYSADMIN_USER/.bash_profile"
    if [[ ! -f "$bash_profile" ]]; then
        log_info "Creating bash profile for '$SYSADMIN_USER'"
        cat > "$bash_profile" << EOF
# .bash_profile
# Get the aliases and functions
if [ -f ~/.bashrc ]; then
    . ~/.bashrc
fi

# User specific environment and startup programs
PATH=\$PATH:\$HOME/.local/bin:\$HOME/bin
export PATH

# Set a nice prompt
export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

# Some useful aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
EOF
        chown "$SYSADMIN_USER:sysadmin" "$bash_profile"
        chmod 644 "$bash_profile"
    fi
    
    update_module_status "users" "completed"
    log_success "User configuration completed successfully"
}

configure_dnf() {
    if [[ "$ENABLE_DNF_TUNING" == "false" ]]; then
        log_info "Skipping DNF configuration"
        return 0
    fi
    
    log_info "Configuring DNF for optimal performance"
    
    local dnf_conf="/etc/dnf/dnf.conf"
    backup_file "$dnf_conf" "dnf.conf"
    
    cat > "$dnf_conf" << 'EOF'
[main]
gpgcheck=1
installonly_limit=3
clean_requirements_on_remove=True
best=True
skip_if_unavailable=True
tsflags=nodocs
deltarpm=True
fastestmirror=True
max_parallel_downloads=10
minrate=1000
timeout=30
zchunk=True
repo_gpgcheck=1
localpkg_gpgcheck=0
protected_packages=dnf,yum
debuglevel=2
logfile=/var/log/dnf.log
keepcache=True
metadata_timer_sync=3600
module_platform_id=platform:el9
countme=False
EOF
    
    log_success "DNF configuration optimized"
}

configure_repositories() {
    if [[ "$ENABLE_REPOS" == "false" ]]; then
        log_info "Skipping repository configuration"
        return 0
    fi
    
    log_info "Configuring additional repositories"
    
    # Enable CRB repository
    log_info "Enabling CRB repository"
    dnf config-manager --set-enabled crb || true
    
    # Install and enable EPEL
    log_info "Installing EPEL repositories"
    dnf -y install epel-release epel-next-release || true
    dnf config-manager --set-enabled epel epel-next || true
    
    # Install REMI repository
    log_info "Installing REMI repository"
    if ! rpm -qa | grep -q remi-release; then
        dnf -y install https://rpms.remirepo.net/enterprise/remi-release-9.rpm || true
    fi
    dnf config-manager --set-enabled remi || true
    
    # Install RPM Fusion
    log_info "Installing RPM Fusion repository"
    if ! rpm -qa | grep -q rpmfusion-free-release; then
        dnf -y install https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-9.noarch.rpm || true
    fi
    
    log_success "Repositories configured successfully"
}

update_system() {
    if [[ "$ENABLE_SYSTEM_UPDATE" == "false" ]]; then
        log_info "Skipping system update"
        return 0
    fi
    
    log_info "Updating system packages"
    
    # Clean metadata and update
    dnf clean all
    dnf makecache --refresh
    
    # Perform system update
    log_info "Performing system upgrade (this may take a while)"
    dnf -y upgrade --refresh
    
    log_success "System update completed"
}

install_essential_tools() {
    if [[ "$ENABLE_TOOLS_INSTALL" == "false" ]]; then
        log_info "Skipping tools installation"
        return 0
    fi
    
    log_info "Installing essential tools and utilities"
    
    # Base tools
    local base_tools=(
        lsof net-tools mlocate screen tmux parallel wget curl nano
        bash-completion jq neofetch pciutils ipset-service dmidecode
        iperf iperf3 nmap socat rpmconf lm_sensors mdadm
        NetworkManager-initscripts-updown git git-core dnf-plugins-core
        cmake kpatch kpatch-dnf dnf-automatic man-db sos
        rsyslog-logrotate yum-utils htop tree unzip zip
        firewalld fail2ban vim-enhanced
    )
    
    log_info "Installing base tools"
    dnf -y install "${base_tools[@]}" || true
    
    # Development Tools group
    log_info "Installing Development Tools group"
    dnf group -y install "Development Tools" || true
    
    # Configure man-db
    log_info "Configuring man-db"
    cat > /etc/sysconfig/man-db << 'EOF'
SERVICE="yes"
CRON="yes"
OPTS="-q"
EOF
    
    # Enable essential services
    log_info "Enabling essential services"
    systemctl enable --now firewalld || true
    
    log_success "Essential tools installed and configured"
}

configure_auto_updates() {
    if [[ "$ENABLE_AUTO_UPDATES" == "false" ]]; then
        log_info "Skipping auto-updates configuration"
        return 0
    fi
    
    log_info "Configuring automatic security updates"
    
    # Ensure dnf-automatic is installed
    dnf -y install dnf-automatic || true
    
    # Configure for security-only updates
    local auto_conf="/etc/dnf/automatic.conf"
    backup_file "$auto_conf" "automatic.conf"
    
    sed -i 's/^apply_updates = no/apply_updates = yes/' "$auto_conf"
    sed -i 's/^upgrade_type = default/upgrade_type = security/' "$auto_conf"
    sed -i 's/^emit_via = stdio/emit_via = email/' "$auto_conf"
    
    # Enable the timer
    systemctl enable --now dnf-automatic.timer
    
    log_success "Automatic security updates configured"
}

# ==== TIME SYNCHRONIZATION MODULE ====
detect_geoip_timezone() {
    log_info "Detecting geographical location for timezone configuration"
    
    local geoip_data
    local detected_timezone
    local public_ip
    
    # Get public IP first
    public_ip=$(curl -s --max-time 10 https://ipinfo.io/ip 2>/dev/null || echo "unknown")
    log_debug "Detected public IP: $public_ip"
    
    # Try multiple GeoIP services for reliability
    local services=(
        "http://ip-api.com/json/"
        "https://ipapi.co/json/"
        "https://freegeoip.app/json/"
    )
    
    for service in "${services[@]}"; do
        log_debug "Trying GeoIP service: $service"
        
        case "$service" in
            *ip-api.com*)
                geoip_data=$(curl -s --max-time 15 "$service" 2>/dev/null || echo "")
                if [[ -n "$geoip_data" ]] && echo "$geoip_data" | jq -e '.timezone' >/dev/null 2>&1; then
                    detected_timezone=$(echo "$geoip_data" | jq -r '.timezone')
                    local country=$(echo "$geoip_data" | jq -r '.country // "Unknown"')
                    local city=$(echo "$geoip_data" | jq -r '.city // "Unknown"')
                    log_info "Location detected: $city, $country"
                    break
                fi
                ;;
            *ipapi.co*)
                geoip_data=$(curl -s --max-time 15 "$service" 2>/dev/null || echo "")
                if [[ -n "$geoip_data" ]] && echo "$geoip_data" | jq -e '.timezone' >/dev/null 2>&1; then
                    detected_timezone=$(echo "$geoip_data" | jq -r '.timezone')
                    local country=$(echo "$geoip_data" | jq -r '.country_name // "Unknown"')
                    local city=$(echo "$geoip_data" | jq -r '.city // "Unknown"')
                    log_info "Location detected: $city, $country"
                    break
                fi
                ;;
            *freegeoip.app*)
                geoip_data=$(curl -s --max-time 15 "$service" 2>/dev/null || echo "")
                if [[ -n "$geoip_data" ]] && echo "$geoip_data" | jq -e '.time_zone' >/dev/null 2>&1; then
                    detected_timezone=$(echo "$geoip_data" | jq -r '.time_zone')
                    local country=$(echo "$geoip_data" | jq -r '.country_name // "Unknown"')
                    local city=$(echo "$geoip_data" | jq -r '.city // "Unknown"')
                    log_info "Location detected: $city, $country"
                    break
                fi
                ;;
        esac
        
        log_debug "Service $service failed or returned invalid data"
    done
    
    # Validate detected timezone
    if [[ -n "$detected_timezone" && "$detected_timezone" != "null" ]]; then
        if [[ -f "/usr/share/zoneinfo/$detected_timezone" ]]; then
            log_success "Valid timezone detected: $detected_timezone"
            echo "$detected_timezone"
            return 0
        else
            log_warn "Detected timezone '$detected_timezone' is not valid"
        fi
    fi
    
    log_warn "Could not detect timezone automatically, using fallback: $FALLBACK_TIMEZONE"
    echo "$FALLBACK_TIMEZONE"
}

configure_time_synchronization() {
    if [[ "$ENABLE_TIME_SYNC" == "false" ]]; then
        log_info "Skipping time synchronization configuration"
        return 0
    fi
    
    log_info "Configuring time synchronization and timezone"
    
    # Install chrony and ntpstat
    log_info "Installing chrony and ntpstat"
    dnf -y install chrony ntpstat || true
    
    # Backup existing chrony configuration
    backup_file "/etc/chrony.conf" "chrony.conf"
    backup_file "/etc/timezone" "timezone"
    backup_file "/etc/localtime" "localtime"
    
    # Create new chrony configuration
    log_info "Configuring chrony with NTP servers"
    cat > /etc/chrony.conf << 'EOF'
# Use public NTP servers from the pool.ntp.org project
# Please consider joining the pool (https://www.pool.ntp.org/join.html)
EOF
    
    # Add configured NTP servers
    for server in "${CHRONY_SERVERS[@]}"; do
        echo "server $server iburst" >> /etc/chrony.conf
        log_debug "Added NTP server: $server"
    done
    
    cat >> /etc/chrony.conf << 'EOF'

# Record the rate at which the system clock gains/loses time
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
# if its offset is larger than 1 second
makestep 1.0 3

# Enable kernel synchronization of the real-time clock (RTC)
rtcsync

# Enable hardware timestamping on all interfaces that support it
#hwtimestamp *

# Increase the minimum number of selectable sources required to adjust
# the system clock
#minsources 2

# Allow NTP client access from local network
#allow 192.168.0.0/16

# Serve time even if not synchronized to a time source
#local stratum 10

# Specify file containing keys for NTP authentication
keyfile /etc/chrony.keys

# Get TAI-UTC offset and leap seconds from the system tz database
leapsectz right/UTC

# Specify directory for log files
logdir /var/log/chrony

# Select which information is logged
#log measurements statistics tracking
EOF
    
    # Detect and configure timezone
    log_info "Detecting geographical timezone"
    local detected_timezone
    detected_timezone=$(detect_geoip_timezone)
    
    if [[ -n "$detected_timezone" ]]; then
        log_info "Setting timezone to: $detected_timezone"
        
        # Set timezone using multiple methods for compatibility
        # Method 1: Using timedatectl (preferred)
        if command -v timedatectl >/dev/null 2>&1; then
            timedatectl set-timezone "$detected_timezone" || true
            log_debug "Timezone set using timedatectl"
        fi
        
        # Method 2: Update /etc/localtime
        if [[ -f "/usr/share/zoneinfo/$detected_timezone" ]]; then
            cp "/usr/share/zoneinfo/$detected_timezone" /etc/localtime || true
            log_debug "Updated /etc/localtime"
        fi
        
        # Method 3: Update /etc/timezone (for compatibility)
        echo "$detected_timezone" > /etc/timezone || true
        log_debug "Updated /etc/timezone"
        
        # Verify timezone setting
        local current_timezone
        current_timezone=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "unknown")
        
        if [[ "$current_timezone" == "$detected_timezone" ]]; then
            log_success "Timezone successfully set to: $detected_timezone"
        else
            log_warn "Timezone verification failed. Expected: $detected_timezone, Got: $current_timezone"
        fi
    else
        log_error "Failed to detect timezone, keeping system default"
    fi
    
    # Start and enable chrony service
    log_info "Starting and enabling chrony service"
    systemctl enable --now chronyd || true
    
    # Wait a moment for chrony to start
    sleep 2
    
    # Force initial time synchronization
    log_info "Forcing initial time synchronization"
    chronyc sources -v || true
    chronyc makestep || true
    
    # Show time synchronization status
    log_info "Time synchronization status:"
    if command -v ntpstat >/dev/null 2>&1; then
        ntpstat || true
    fi
    
    # Show current time and timezone
    log_info "Current system time: $(date)"
    log_info "Current timezone: $(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo 'unknown')"
    
    # Show chrony tracking info
    log_debug "Chrony tracking information:"
    chronyc tracking || true
    
    log_success "Time synchronization configured successfully"
}

# ==== KERNEL MODULES MANAGEMENT ====
detect_cpu_info() {
    log_info "Detecting CPU information and virtualization support"
    
    # Detect CPU vendor
    if [[ -f /proc/cpuinfo ]]; then
        CPU_VENDOR=$(grep -m1 "vendor_id" /proc/cpuinfo | cut -d: -f2 | tr -d ' ' || echo "unknown")
        CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | sed 's/^[ \t]*//' || echo "unknown")
        
        log_info "CPU Vendor: $CPU_VENDOR"
        log_info "CPU Model: $CPU_MODEL"
    else
        log_warn "Unable to read /proc/cpuinfo - CPU detection may be incomplete"
        CPU_VENDOR="unknown"
        CPU_MODEL="unknown"
    fi
    
    # Check for virtualization support
    local virt_flags=""
    if [[ -f /proc/cpuinfo ]]; then
        virt_flags=$(grep -m1 "flags" /proc/cpuinfo | cut -d: -f2 || echo "")
    fi
    
    # Check for Intel VT-x or AMD-V support
    if [[ "$virt_flags" =~ vmx ]]; then
        VIRTUALIZATION_SUPPORT="Intel VT-x"
        log_success "Intel VT-x virtualization support detected"
    elif [[ "$virt_flags" =~ svm ]]; then
        VIRTUALIZATION_SUPPORT="AMD-V"
        log_success "AMD-V virtualization support detected"
    else
        VIRTUALIZATION_SUPPORT="none"
        log_warn "No hardware virtualization support detected"
    fi
    
    # Additional checks using other methods
    if command -v lscpu >/dev/null 2>&1; then
        local lscpu_virt=$(lscpu | grep -i virtualization || echo "")
        if [[ -n "$lscpu_virt" ]]; then
            log_debug "lscpu virtualization info: $lscpu_virt"
        fi
    fi
    
    # Check if we're running in a VM
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local detect_virt=$(systemd-detect-virt 2>/dev/null || echo "none")
        if [[ "$detect_virt" != "none" ]]; then
            log_info "Running in virtualized environment: $detect_virt"
            if [[ "$detect_virt" == "kvm" || "$detect_virt" == "vmware" || "$detect_virt" == "hyperv" ]]; then
                log_warn "Nested virtualization may have limited performance"
            fi
        fi
    fi
}

configure_kernel_modules() {
    if [[ "$ENABLE_KERNEL_MODULES" == "false" ]]; then
        log_info "Skipping kernel modules configuration"
        return 0
    fi
    
    log_info "Configuring kernel modules for system optimization and virtualization"
    
    # Detect CPU information first
    detect_cpu_info
    
    # Backup existing module configurations
    backup_directory "/etc/modules-load.d" "modules-load.d"
    backup_directory "/etc/modprobe.d" "modprobe.d"
    
    # Regenerate module dependencies
    log_info "Regenerating kernel module dependencies"
    /sbin/depmod -a || true
    
    # Define kernel modules to load
    declare -A MODULES_CONF
    
    # Common modules for all systems
    MODULES_CONF=(
        [loop]="options loop max_loop=255"
        [8021q]=""
        [vhost_net]=""
        [vhost_vsock]=""
        [vsock]=""
        [overlay]=""
        [fuse]=""
        [br_netfilter]=""
        [tcp_bbr]=""
        [nf_conntrack]=""
        [xt_CHECKSUM]=""
        [ip_tables]=""
        [ip6_tables]=""
        [nf_nat]=""
        [iptable_nat]=""
        [ip6table_nat]=""
    )
    
    # Add CPU-specific KVM modules if virtualization is supported
    if [[ "$VIRTUALIZATION_SUPPORT" == "Intel VT-x" ]]; then
        log_info "Adding Intel KVM modules"
        MODULES_CONF[kvm_intel]="options kvm_intel nested=1
options kvm_intel enable_shadow_vmcs=1
options kvm_intel enable_apicv=1
options kvm_intel ept=1"
    elif [[ "$VIRTUALIZATION_SUPPORT" == "AMD-V" ]]; then
        log_info "Adding AMD KVM modules"
        MODULES_CONF[kvm_amd]="options kvm_amd nested=1
options kvm_amd enable_shadow_vmcs=1
options kvm_amd enable_apicv=1
options kvm_amd ept=1"
    else
        log_warn "No virtualization support detected - skipping KVM modules"
    fi
    
    # Create modules-load.d directory if it doesn't exist
    mkdir -p /etc/modules-load.d
    mkdir -p /etc/modprobe.d
    
    # Load modules and create configuration files
    local loaded_modules=()
    local failed_modules=()
    local critical_modules=("loop" "overlay" "fuse" "br_netfilter")
    
    for module in "${!MODULES_CONF[@]}"; do
        log_info "Loading kernel module: $module"
        
        # Check if module exists in kernel
        if ! modinfo "$module" &>/dev/null; then
            log_warn "Module $module not found in kernel - skipping"
            failed_modules+=("$module")
            continue
        fi
        
        if modprobe "$module" 2>/dev/null; then
            # Create modules-load.d configuration
            echo "$module" > "/etc/modules-load.d/${module}.conf"
            
            # Create modprobe.d configuration if options exist
            if [[ -n "${MODULES_CONF[$module]}" ]]; then
                echo "${MODULES_CONF[$module]}" > "/etc/modprobe.d/${module}.conf"
                log_debug "Created modprobe configuration for $module"
            fi
            
            # Verify module is loaded
            if lsmod | grep -q "^$module"; then
                log_success "Module $module loaded successfully"
                loaded_modules+=("$module")
            else
                log_warn "Module $module loaded but not visible in lsmod"
                loaded_modules+=("$module")
            fi
        else
            log_warn "Failed to load module: $module"
            failed_modules+=("$module")
            
            # Check if this is a critical module
            if [[ " ${critical_modules[@]} " =~ " $module " ]]; then
                log_error "Critical module $module failed to load - system may not function properly"
            fi
        fi
    done
    
    # Load base KVM module if virtualization modules were loaded
    if [[ "$VIRTUALIZATION_SUPPORT" != "none" ]]; then
        log_info "Loading base KVM module"
        if modprobe kvm 2>/dev/null; then
            echo "kvm" > "/etc/modules-load.d/kvm.conf"
            log_success "Base KVM module loaded successfully"
        else
            log_warn "Failed to load base KVM module"
        fi
    fi
    
    # Configure systemd-modules-load service
    log_info "Configuring systemd-modules-load service"
    systemctl daemon-reexec || true
    systemctl daemon-reload || true
    systemctl enable systemd-modules-load.service || true
    systemctl restart systemd-modules-load.service || true
    
    # Verify service status
    if systemctl is-active --quiet systemd-modules-load.service; then
        log_success "systemd-modules-load service is active"
    else
        log_warn "systemd-modules-load service is not active"
        # Try to get more information
        log_debug "systemd-modules-load service status:"
        systemctl status systemd-modules-load.service --no-pager --lines=5 || true
    fi
    
    # Configure sysctl for network optimization
    log_info "Configuring sysctl parameters for network optimization"
    cat > /etc/sysctl.d/99-network-optimization.conf << 'EOF'
# Network optimization settings
# TCP congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Buffer sizes
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216

# TCP optimizations
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_fastopen = 3

# Connection tracking
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200

# General network optimizations
net.core.netdev_max_backlog = 5000
net.core.netdev_budget = 600
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 10

# Security enhancements
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
EOF
    
    # Apply sysctl settings
    if sysctl --system; then
        log_success "Sysctl settings applied successfully"
        
        # Verify critical settings
        local bbr_status=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
        local qdisc_status=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
        
        log_info "TCP congestion control: $bbr_status"
        log_info "Default qdisc: $qdisc_status"
        
        if [[ "$bbr_status" == "bbr" ]]; then
            log_success "BBR congestion control is active"
        else
            log_warn "BBR congestion control is not active (may require tcp_bbr module)"
        fi
    else
        log_warn "Failed to apply some sysctl settings"
    fi
    
    # Summary
    log_info "Kernel modules configuration summary:"
    log_info "  CPU: $CPU_VENDOR - $CPU_MODEL"
    log_info "  Virtualization: $VIRTUALIZATION_SUPPORT"
    log_info "  Loaded modules: ${#loaded_modules[@]}"
    log_info "  Failed modules: ${#failed_modules[@]}"
    
    if [[ ${#loaded_modules[@]} -gt 0 ]]; then
        log_debug "Successfully loaded: ${loaded_modules[*]}"
    fi
    
    if [[ ${#failed_modules[@]} -gt 0 ]]; then
        log_debug "Failed to load: ${failed_modules[*]}"
    fi
    
    # Verify critical modules for virtualization
    if [[ "$VIRTUALIZATION_SUPPORT" != "none" ]]; then
        log_info "Verifying virtualization modules"
        if lsmod | grep -q "kvm"; then
            log_success "KVM modules are properly loaded"
            
            # Check KVM device nodes
            if [[ -e /dev/kvm ]]; then
                log_success "KVM device node (/dev/kvm) is available"
            else
                log_warn "KVM device node (/dev/kvm) is not available"
            fi
            
            # Check nested virtualization if enabled
            if [[ "$CPU_VENDOR" == "GenuineIntel" ]]; then
                local nested_status=$(cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || echo "unknown")
                log_debug "Intel nested virtualization: $nested_status"
            elif [[ "$CPU_VENDOR" == "AuthenticAMD" ]]; then
                local nested_status=$(cat /sys/module/kvm_amd/parameters/nested 2>/dev/null || echo "unknown")
                log_debug "AMD nested virtualization: $nested_status"
            fi
        else
            log_warn "KVM modules not found in lsmod - virtualization may not work"
        fi
    fi
    
    log_success "Kernel modules configuration completed"
}

# ==== COCKPIT WEB MANAGEMENT ====
configure_cockpit_management() {
    if [[ "$ENABLE_COCKPIT_MANAGEMENT" == "false" ]]; then
        log_info "Skipping Cockpit web management configuration"
        return 0
    fi
    
    log_info "Configuring Cockpit web management interface"
    
    # Backup existing configurations
    backup_file "/etc/pam.d/cockpit" "cockpit_pam"
    backup_file "/etc/cockpit/disallowed-users" "cockpit_disallowed_users"
    backup_directory "/etc/systemd/system/cockpit.socket.d" "cockpit_socket_d"
    
    # Install Cockpit packages
    log_info "Installing Cockpit and PCP packages"
    
    # Ensure EPEL is available (should already be installed by repos module)
    if ! rpm -qa | grep -q epel-release; then
        dnf install -y epel-release || true
    fi
    
    # Install Cockpit and monitoring packages
    local cockpit_packages=(
        cockpit
        cockpit-ws
        cockpit-bridge
        cockpit-system
        cockpit-session-recording
        cockpit-storaged
        cockpit-packagekit
        cockpit-networkmanager
        cockpit-selinux
        cockpit-kdump
        pcp
        python3-pcp
        bind-utils
    )
    
    log_info "Installing Cockpit packages: ${cockpit_packages[*]}"
    dnf install -y "${cockpit_packages[@]}" || true
    
    # Configure Cockpit socket to listen on custom port
    log_info "Configuring Cockpit to listen on port $COCKPIT_PORT"
    
    local systemd_socket_dir="/etc/systemd/system/cockpit.socket.d"
    mkdir -p "$systemd_socket_dir"
    
    cat > "$systemd_socket_dir/listen.conf" << EOF
[Socket]
ListenStream=
ListenStream=$COCKPIT_PORT
EOF
    
    # Create cockpit-admin group using improved method
    log_info "Creating Cockpit administration group: $COCKPIT_GROUP"
    if ! create_group_safe "$COCKPIT_GROUP" "Cockpit administrators group"; then
        log_error "Failed to create Cockpit admin group"
        return 1
    fi
    
    # Configure PAM restrictions for Cockpit access
    log_info "Configuring PAM restrictions for Cockpit access"
    
    cat > "/etc/pam.d/cockpit" << EOF
# PAM configuration for Cockpit shell access
# Only allow users in the cockpit-admin group
auth     required pam_succeed_if.so user ingroup $COCKPIT_GROUP
auth     include  password-auth
account  include  password-auth
password include  password-auth
session  include  password-auth
EOF
    
    # Block root login to Cockpit
    log_info "Blocking root login to Cockpit"
    mkdir -p "/etc/cockpit"
    cat > "/etc/cockpit/disallowed-users" << EOF
# Users not allowed to login to Cockpit
root
EOF
    
    # Add sysadmin user to cockpit-admin group if user creation is enabled
    if [[ "$ENABLE_USER_CREATION" == "true" ]] && id "$SYSADMIN_USER" &>/dev/null; then
        log_info "Adding $SYSADMIN_USER to $COCKPIT_GROUP group"
        usermod -aG "$COCKPIT_GROUP" "$SYSADMIN_USER"
        log_success "User $SYSADMIN_USER added to $COCKPIT_GROUP group"
    fi
    
    # Configure firewall for Cockpit using improved method
    log_info "Configuring firewall for Cockpit"
    configure_firewall_port "$COCKPIT_PORT" "tcp" "Cockpit Web UI"
    configure_firewall_port "$PCP_EXPORT_PORT" "tcp" "PCP Prometheus Export"
    
    # Enable and start Cockpit service
    log_info "Enabling and starting Cockpit service"
    systemctl daemon-reload || true
    systemctl enable --now cockpit.socket || true
    
    # Wait for service to start
    sleep 2
    
    # Verify Cockpit is running
    if systemctl is-active --quiet cockpit.socket; then
        log_success "Cockpit service is running"
    else
        log_error "Cockpit service failed to start"
        log_debug "Cockpit socket status:"
        systemctl status cockpit.socket --no-pager --lines=5 || true
    fi
    
    # Enable PCP services for monitoring
    log_info "Enabling PCP services for system monitoring"
    
    # Start PCP collector daemon
    systemctl enable --now pmcd || true
    
    # Start PCP proxy for web access and Prometheus metrics
    systemctl enable --now pmproxy || true
    
    # Wait for services to start
    sleep 2
    
    # Verify PCP services
    if systemctl is-active --quiet pmcd; then
        log_success "PCP collector (pmcd) is running"
    else
        log_warn "PCP collector (pmcd) failed to start"
    fi
    
    if systemctl is-active --quiet pmproxy; then
        log_success "PCP proxy (pmproxy) is running"
    else
        log_warn "PCP proxy (pmproxy) failed to start"
    fi
    
    # Disable kdump if it exists to prevent cockpit errors
    if systemctl list-unit-files | grep -q kdump.service; then
        log_info "Disabling kdump service to prevent Cockpit errors"
        systemctl disable --now kdump.service 2>/dev/null || true
    fi
    
    # Create Cockpit configuration for better defaults
    log_info "Creating Cockpit configuration"
    mkdir -p "/etc/cockpit"
    
    cat > "/etc/cockpit/cockpit.conf" << EOF
[WebService]
# Cockpit configuration
Origins = https://localhost:$COCKPIT_PORT wss://localhost:$COCKPIT_PORT
ProtocolHeader = X-Forwarded-Proto
LoginTitle = $(hostname 2>/dev/null || echo "AlmaLinux") System Management
LoginTo = false
RequireHost = true
MaxStartups = 10
EOF
    
    # Test Cockpit accessibility
    log_info "Testing Cockpit accessibility"
    
    # Get the IP address for access URL
    local access_ip=""
    if [[ -n "$PUBLIC_IPV4" ]]; then
        access_ip="$PUBLIC_IPV4"
    elif [[ -n "$CURRENT_HOSTNAME" ]]; then
        access_ip="$CURRENT_HOSTNAME"
    else
        access_ip="$(hostname -I | awk '{print $1}' || echo 'localhost')"
    fi
    
    # Test if Cockpit is responding
    if curl -k -s --connect-timeout 5 "https://localhost:$COCKPIT_PORT" >/dev/null 2>&1; then
        log_success "Cockpit is responding on port $COCKPIT_PORT"
    else
        log_warn "Cockpit may not be responding on port $COCKPIT_PORT"
    fi
    
    # Configure log rotation for Cockpit
    log_info "Configuring log rotation for Cockpit"
    cat > "/etc/logrotate.d/cockpit" << EOF
/var/log/cockpit/* {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        /bin/systemctl reload cockpit.socket > /dev/null 2>&1 || true
    endscript
}
EOF
    
    # Summary and access information
    log_success "Cockpit web management interface configured successfully"
    log_info "Cockpit configuration summary:"
    log_info "  Web Interface: https://$access_ip:$COCKPIT_PORT"
    log_info "  Admin Group: $COCKPIT_GROUP"
    log_info "  Prometheus Metrics: http://$access_ip:$PCP_EXPORT_PORT/metrics"
    log_info "  Allowed Users: Members of $COCKPIT_GROUP group"
    log_info "  Blocked Users: root"
    
    # Show current group members
    local group_members=$(getent group "$COCKPIT_GROUP" | cut -d: -f4)
    if [[ -n "$group_members" ]]; then
        log_info "  Current Members: $group_members"
    else
        log_info "  Current Members: none"
    fi
    
    # Additional security recommendations
    log_info "Security recommendations:"
    log_info "  - Access Cockpit only via HTTPS"
    log_info "  - Consider using a reverse proxy for production"
    log_info "  - Regularly review user access to $COCKPIT_GROUP group"
    log_info "  - Monitor access logs in /var/log/cockpit/"
    
    update_module_status "cockpit" "completed"
    log_success "Cockpit web management configuration completed"
}

cleanup_system() {
    log_info "Cleaning up system"
    
    # Remove old kernels and packages
    dnf -y remove --oldinstallonly || true
    dnf -y autoremove || true
    
    # Clean package cache
    dnf clean all
    
    # Remove temporary files
    rm -f /installimage.conf 2>/dev/null || true
    
    # Update man database
    mandb -q || true
    
    # Update locate database
    updatedb || true
    
    log_success "System cleanup completed"
}

# ==== MAIN EXECUTION FLOW ====
main() {
    log_info "Starting AlmaLinux 9+ Bootstrap Script v$SCRIPT_VERSION"
    
    # Pre-flight checks
    check_root
    check_os
    acquire_lock
    
    # Interactive credential setup
    prompt_for_credentials
    
    # Validate passwords after potential interactive input
    validate_passwords
    
    # Create backup directory if rollback is enabled
    if [[ "$ENABLE_ROLLBACK_SUPPORT" == "true" ]]; then
        create_backup_directory
    fi
    
    # Execute configuration modules
    configure_selinux
    configure_hostname
    create_users
    configure_dnf
    configure_repositories
    update_system
    install_essential_tools
    configure_auto_updates
    configure_time_synchronization
    configure_kernel_modules
    configure_cockpit_management
    cleanup_system
    
    # Create rollback script
    if [[ "$ENABLE_ROLLBACK_SUPPORT" == "true" ]]; then
        create_rollback_script
    fi
    
    # Final status
    log_success "Bootstrap initialization completed successfully!"
    log_info "Backup created at: $BACKUP_DIR"
    log_info "Log file: $LOG_FILE"
    
    # Reboot prompt
    if [[ "$SKIP_REBOOT_PROMPT" == "false" && "$NON_INTERACTIVE" == "false" ]]; then
        echo
        read -p "A reboot is recommended to complete the setup. Reboot now? [y/N]: " -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Rebooting system..."
            reboot
        fi
    elif [[ "$SKIP_REBOOT_PROMPT" == "false" && "$NON_INTERACTIVE" == "true" ]]; then
        log_info "Non-interactive mode: Skipping reboot prompt"
        log_warn "Please reboot the system manually when convenient"
    fi
}

# ==== ARGUMENT PARSING ====
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            -n|--non-interactive)
                NON_INTERACTIVE=true
                shift
                ;;
            --load-config)
                LOAD_CONFIG=true
                shift
                ;;
            --json-logging)
                JSON_LOGGING=true
                shift
                ;;
            --stage)
                STAGE_MODE="$2"
                shift 2
                ;;
            --force-stage)
                FORCE_STAGE=true
                shift
                ;;
            --reset-state)
                RESET_STATE=true
                shift
                ;;
            --show-state)
                SHOW_STATE=true
                shift
                ;;
            -H|--hostname)
                HOSTNAME="$2"
                shift 2
                ;;
            -u|--sysadmin-user)
                SYSADMIN_USER="$2"
                shift 2
                ;;
            -p|--sysadmin-pass)
                SYSADMIN_PASS="$2"
                SYSADMIN_PASS_PROVIDED=true
                shift 2
                ;;
            -r|--root-pass)
                ROOT_PASS="$2"
                ROOT_PASS_PROVIDED=true
                shift 2
                ;;
            --skip-selinux)
                ENABLE_SELINUX_CONFIG=false
                shift
                ;;
            --skip-hostname)
                ENABLE_HOSTNAME_CONFIG=false
                shift
                ;;
            --skip-users)
                ENABLE_USER_CREATION=false
                shift
                ;;
            --skip-dnf-tuning)
                ENABLE_DNF_TUNING=false
                shift
                ;;
            --skip-repos)
                ENABLE_REPOS=false
                shift
                ;;
            --skip-updates)
                ENABLE_SYSTEM_UPDATE=false
                shift
                ;;
            --skip-tools)
                ENABLE_TOOLS_INSTALL=false
                shift
                ;;
            --skip-auto-updates)
                ENABLE_AUTO_UPDATES=false
                shift
                ;;
            --skip-time-sync)
                ENABLE_TIME_SYNC=false
                shift
                ;;
            --skip-kernel-modules)
                ENABLE_KERNEL_MODULES=false
                shift
                ;;
            --skip-cockpit)
                ENABLE_COCKPIT_MANAGEMENT=false
                shift
                ;;
            --skip-rollback)
                ENABLE_ROLLBACK_SUPPORT=false
                shift
                ;;
            --skip-reboot-prompt)
                SKIP_REBOOT_PROMPT=true
                shift
                ;;
            --rollback)
                if [[ -n "${2:-}" ]]; then
                    perform_rollback "$2"
                else
                    echo "Available backups:"
                    list_backups
                    echo
                    read -p "Enter backup path to rollback: " -r backup_path
                    perform_rollback "$backup_path"
                fi
                exit 0
                ;;
            --list-backups)
                list_backups
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Handle stage mode
    if [[ -n "$STAGE_MODE" ]]; then
        log_info "Stage mode enabled: $STAGE_MODE"
        
        # Disable all modules first
        ENABLE_SELINUX_CONFIG=false
        ENABLE_HOSTNAME_CONFIG=false
        ENABLE_USER_CREATION=false
        ENABLE_DNF_TUNING=false
        ENABLE_REPOS=false
        ENABLE_SYSTEM_UPDATE=false
        ENABLE_TOOLS_INSTALL=false
        ENABLE_AUTO_UPDATES=false
        ENABLE_TIME_SYNC=false
        ENABLE_KERNEL_MODULES=false
        ENABLE_COCKPIT_MANAGEMENT=false
        
        # Enable only the specified stage
        case "$STAGE_MODE" in
            selinux)
                ENABLE_SELINUX_CONFIG=true
                ;;
            hostname)
                ENABLE_HOSTNAME_CONFIG=true
                ;;
            users)
                ENABLE_USER_CREATION=true
                ;;
            dnf)
                ENABLE_DNF_TUNING=true
                ;;
            repos)
                ENABLE_REPOS=true
                ;;
            updates)
                ENABLE_SYSTEM_UPDATE=true
                ;;
            tools)
                ENABLE_TOOLS_INSTALL=true
                ;;
            auto-updates)
                ENABLE_AUTO_UPDATES=true
                ;;
            time-sync)
                ENABLE_TIME_SYNC=true
                ;;
            kernel-modules)
                ENABLE_KERNEL_MODULES=true
                ;;
            cockpit)
                ENABLE_COCKPIT_MANAGEMENT=true
                ;;
            *)
                log_error "Unknown stage: $STAGE_MODE"
                log_error "Valid stages: selinux, hostname, users, dnf, repos, updates, tools, auto-updates, time-sync, kernel-modules, cockpit"
                exit 1
                ;;
        esac
    fi
}

# ==== SCRIPT ENTRY POINT ====
    # Initialize logging
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    # Initialize status tracking
    init_status_file
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Load configuration if requested
    if [[ "$LOAD_CONFIG" == "true" ]]; then
        load_config
    fi
    
    # Execute main function
    main

    # Exit successfully
    exit 0
}
