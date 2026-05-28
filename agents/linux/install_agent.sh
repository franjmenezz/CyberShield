#!/bin/bash
# ==============================================================================
# CyberShield — Linux Agent Installer
# ==============================================================================
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.
#
# DESCRIPTION:
#   Installs and configures the CyberShield agent on Linux systems.
#   Supports: Ubuntu 20.04/22.04 LTS, Debian 11/12, RHEL/CentOS 8/9
#   This script:
#     1. Installs Wazuh Agent
#     2. Configures auditd rules for CyberShield
#     3. Installs the CyberShield event forwarder daemon
#     4. Registers the device with the CyberShield API
#
# REQUIREMENTS:
#   - Root or sudo access
#   - curl, jq, openssl
#
# USAGE:
#   sudo bash install_agent.sh \
#     --server "https://cybershield.yourcompany.com" \
#     --token  "your-agent-token-here" \
#     --name   "Servidor Web 01"
#
# ==============================================================================

set -euo pipefail

# ── CONFIGURATION ──────────────────────────────────────────────────────────────
CS_VERSION="1.0.0"
CS_INSTALL_DIR="/opt/cybershield"
CS_CONFIG_DIR="/etc/cybershield"
CS_LOG_DIR="/var/log/cybershield"
CS_SERVICE_NAME="cybershield-agent"
CS_USER="cybershield"
WAZUH_VERSION="4.7.3"

# ── COLORS ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; NC='\033[0m'

log()     { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]${NC} $*" | tee -a "$CS_LOG_DIR/install.log" 2>/dev/null || echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [OK]${NC} $*" | tee -a "$CS_LOG_DIR/install.log" 2>/dev/null || echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]${NC} $*" | tee -a "$CS_LOG_DIR/install.log" 2>/dev/null || echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR]${NC} $*" | tee -a "$CS_LOG_DIR/install.log" 2>/dev/null || echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

banner() {
    echo ""
    echo -e "${PURPLE}  ╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}  ║          🛡️  CyberShield Agent Installer              ║${NC}"
    echo -e "${PURPLE}  ║          Version ${CS_VERSION} — Linux Edition               ║${NC}"
    echo -e "${PURPLE}  ║  Copyright (c) 2025 Francisco José Jiménez Pozo    ║${NC}"
    echo -e "${PURPLE}  ╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ── ARGUMENT PARSING ───────────────────────────────────────────────────────────
SERVER_URL=""
AGENT_TOKEN=""
DEVICE_NAME=""
WAZUH_MANAGER=""
SKIP_WAZUH=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --server)  SERVER_URL="$2";    shift 2 ;;
        --token)   AGENT_TOKEN="$2";   shift 2 ;;
        --name)    DEVICE_NAME="$2";   shift 2 ;;
        --wazuh)   WAZUH_MANAGER="$2"; shift 2 ;;
        --skip-wazuh) SKIP_WAZUH=true; shift ;;
        *) error "Unknown argument: $1" ;;
    esac
done

# ── VALIDATE ───────────────────────────────────────────────────────────────────
validate_inputs() {
    log "Validating installation parameters..."
    [[ -z "$SERVER_URL" ]]   && error "--server is required"
    [[ -z "$AGENT_TOKEN" ]]  && error "--token is required"
    [[ -z "$DEVICE_NAME" ]]  && error "--name is required"
    [[ ${#AGENT_TOKEN} -lt 32 ]] && error "Agent token appears invalid (too short)"
    [[ "$SERVER_URL" =~ ^https?:// ]] || error "ServerURL must start with http:// or https://"
    success "Parameters validated"
}

# ── CHECK DEPENDENCIES ─────────────────────────────────────────────────────────
check_deps() {
    log "Checking dependencies..."
    local deps=("curl" "jq" "openssl" "auditd" "python3")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log "Installing missing dependencies: ${missing[*]}"
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq "${missing[@]}" auditd audispd-plugins
        elif command -v yum &>/dev/null; then
            yum install -y -q "${missing[@]}" audit
        else
            error "Cannot install dependencies — unsupported package manager"
        fi
    fi
    success "All dependencies available"
}

# ── SYSTEM INFO ────────────────────────────────────────────────────────────────
get_system_info() {
    CS_HOSTNAME=$(hostname -f)
    CS_OS=$(. /etc/os-release && echo "$NAME $VERSION_ID")
    CS_IP=$(ip route get 1 | awk '{print $7; exit}' 2>/dev/null || hostname -I | awk '{print $1}')
    CS_MAC=$(ip link show | awk '/ether/ {print $2; exit}')
    CS_ARCH=$(uname -m)
    CS_KERNEL=$(uname -r)
    log "System: $CS_HOSTNAME | $CS_OS | IP: $CS_IP"
}

# ── CREATE DIRECTORIES & USER ──────────────────────────────────────────────────
setup_directories() {
    log "Setting up directories..."
    mkdir -p "$CS_INSTALL_DIR" "$CS_CONFIG_DIR" "$CS_LOG_DIR"

    # Create dedicated non-root user for the agent
    if ! id "$CS_USER" &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$CS_USER"
        success "Created system user: $CS_USER"
    fi

    chown -R "$CS_USER:$CS_USER" "$CS_LOG_DIR"
    chmod 750 "$CS_LOG_DIR"
    chmod 700 "$CS_CONFIG_DIR"
}

# ── CONFIGURE AUDITD ───────────────────────────────────────────────────────────
configure_auditd() {
    log "Configuring auditd rules for CyberShield..."

    cat > /etc/audit/rules.d/cybershield.rules << 'AUDITEOF'
# CyberShield Audit Rules v1.0
# Copyright (c) 2025 Francisco José Jiménez Pozo — All rights reserved.

# Delete all existing rules
-D

# Set buffer size
-b 8192

# Authentication events
-w /etc/passwd -p wa -k cybershield_passwd
-w /etc/shadow -p wa -k cybershield_shadow
-w /etc/group -p wa -k cybershield_group
-w /etc/sudoers -p wa -k cybershield_sudoers
-w /etc/sudoers.d/ -p wa -k cybershield_sudoers

# SSH events
-w /etc/ssh/sshd_config -p wa -k cybershield_ssh
-w /var/log/auth.log -p wa -k cybershield_auth
-w /var/log/secure -p wa -k cybershield_auth

# Privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k cybershield_sudo
-a always,exit -F path=/usr/bin/su -F perm=x -k cybershield_su
-a always,exit -F path=/usr/bin/passwd -F perm=x -k cybershield_passwd_cmd

# Network configuration changes
-w /etc/hosts -p wa -k cybershield_network
-w /etc/network/ -p wa -k cybershield_network
-w /etc/NetworkManager/ -p wa -k cybershield_network

# Crontab changes
-w /etc/cron.d/ -p wa -k cybershield_cron
-w /etc/crontab -p wa -k cybershield_cron
-w /var/spool/cron/ -p wa -k cybershield_cron

# Kernel modules
-w /sbin/insmod -p x -k cybershield_modules
-w /sbin/rmmod -p x -k cybershield_modules
-w /sbin/modprobe -p x -k cybershield_modules

# Systemd service changes
-w /etc/systemd/system/ -p wa -k cybershield_systemd
-w /lib/systemd/system/ -p wa -k cybershield_systemd

# User/group management syscalls
-a always,exit -F arch=b64 -S useradd,userdel,usermod,groupadd,groupdel,groupmod -k cybershield_user_mgmt
-a always,exit -F arch=b32 -S useradd,userdel,usermod,groupadd,groupdel,groupmod -k cybershield_user_mgmt

# Privilege escalation detection
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -k cybershield_priv
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid -k cybershield_priv

# Process execution
-a always,exit -F arch=b64 -S execve -k cybershield_exec
-a always,exit -F arch=b32 -S execve -k cybershield_exec

# File access in /tmp (malware staging area)
-w /tmp -p wxa -k cybershield_tmp
-w /var/tmp -p wxa -k cybershield_tmp

# Make rules immutable (comment out during initial testing)
# -e 2
AUDITEOF

    # Reload auditd rules
    if command -v augenrules &>/dev/null; then
        augenrules --load 2>/dev/null || true
    fi
    service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true
    success "auditd configured with CyberShield rules"
}

# ── INSTALL WAZUH AGENT ────────────────────────────────────────────────────────
install_wazuh() {
    if [[ "$SKIP_WAZUH" == "true" ]]; then
        log "Skipping Wazuh installation (--skip-wazuh)"
        return
    fi

    log "Installing Wazuh Agent $WAZUH_VERSION..."

    if command -v apt-get &>/dev/null; then
        # Debian/Ubuntu
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
            gpg --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
            > /etc/apt/sources.list.d/wazuh.list
        apt-get update -qq
        WAZUH_AGENT_NAME="$DEVICE_NAME" \
        WAZUH_MANAGER="${WAZUH_MANAGER:-localhost}" \
        apt-get install -y wazuh-agent 2>/dev/null || warn "Wazuh apt install failed — continuing"

    elif command -v rpm &>/dev/null; then
        # RHEL/CentOS
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH 2>/dev/null || true
        cat > /etc/yum.repos.d/wazuh.repo << 'YUMEOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
YUMEOF
        WAZUH_MANAGER="${WAZUH_MANAGER:-localhost}" \
        yum install -y wazuh-agent 2>/dev/null || warn "Wazuh yum install failed — continuing"
    fi

    success "Wazuh Agent installation attempted"
}

# ── CREATE FORWARDER DAEMON ────────────────────────────────────────────────────
create_forwarder() {
    log "Creating CyberShield event forwarder daemon..."

    # Write config
    cat > "$CS_CONFIG_DIR/config.json" << CONFEOF
{
    "version": "$CS_VERSION",
    "server_url": "$SERVER_URL",
    "agent_token": "$AGENT_TOKEN",
    "device_name": "$DEVICE_NAME",
    "hostname": "$CS_HOSTNAME",
    "ip_address": "$CS_IP",
    "mac_address": "$CS_MAC",
    "os": "$CS_OS",
    "poll_interval": 30,
    "log_dir": "$CS_LOG_DIR",
    "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
CONFEOF
    chmod 600 "$CS_CONFIG_DIR/config.json"
    chown root:root "$CS_CONFIG_DIR/config.json"

    # Write Python forwarder
    cat > "$CS_INSTALL_DIR/forwarder.py" << 'PYEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# CyberShield Event Forwarder — Linux
# Copyright (c) 2025 Francisco José Jiménez Pozo — All rights reserved.

import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

CONFIG_PATH = "/etc/cybershield/config.json"
LOG_PATH    = "/var/log/cybershield/forwarder.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("cybershield")


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def compute_signature(token: str, body: str) -> str:
    """Compute HMAC-SHA256 signature of the request body."""
    return hmac.new(
        token.encode('utf-8'),
        body.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def send_event(config: dict, event: dict) -> bool:
    """Send a security event to the CyberShield API with HMAC authentication."""
    body = json.dumps(event, ensure_ascii=True, separators=(',', ':'))
    signature = compute_signature(config['agent_token'], body)

    req = urllib.request.Request(
        url=f"{config['server_url']}/cybershield/api/v1/event",
        data=body.encode('utf-8'),
        headers={
            'Content-Type': 'application/json',
            'X-CyberShield-Token': config['agent_token'],
            'X-CyberShield-Signature': signature,
        },
        method='POST'
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result.get('success'):
                logger.debug(f"Event sent — Log UID: {result.get('log_uid', 'unknown')}")
                return True
    except urllib.error.HTTPError as e:
        logger.warning(f"HTTP {e.code} sending event: {e.reason}")
    except Exception as e:
        logger.error(f"Failed to send event: {e}")
    return False


def parse_auth_log(config: dict):
    """Parse /var/log/auth.log for authentication events."""
    auth_log = "/var/log/auth.log" if Path("/var/log/auth.log").exists() else "/var/log/secure"

    if not Path(auth_log).exists():
        return

    patterns = {
        'login': (
            re.compile(r'Accepted (?:password|publickey) for (\S+) from ([\d.]+)'),
            'login', 'high'
        ),
        'login_failed': (
            re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.]+)'),
            'login_failed', 'high'
        ),
        'sudo': (
            re.compile(r'sudo:.*COMMAND=(.+)$'),
            'privilege_escalation', 'critical'
        ),
        'user_created': (
            re.compile(r'useradd.*new user.*name=(\S+)'),
            'user_created', 'critical'
        ),
        'user_deleted': (
            re.compile(r'userdel.*user \'(\S+)\''),
            'user_deleted', 'critical'
        ),
    }

    try:
        result = subprocess.run(
            ['tail', '-n', '20', auth_log],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            for key, (pattern, event_type, severity) in patterns.items():
                m = pattern.search(line)
                if m:
                    source_ip = m.group(2) if len(m.groups()) > 1 else ''
                    user = m.group(1)
                    event = {
                        'event_type': event_type,
                        'severity': severity,
                        'description': line.strip()[:500],
                        'user_name': user,
                        'source_ip': source_ip,
                        'wazuh_rule_id': f'LINUX-AUTH-{key.upper()}',
                    }
                    send_event(config, event)
                    break
    except Exception as e:
        logger.debug(f"auth.log parse error: {e}")


def check_network_connections(config: dict):
    """Check for suspicious outbound connections."""
    suspicious_ports = {22, 23, 3389, 4444, 1433, 5432, 6667, 31337}
    try:
        result = subprocess.run(
            ['ss', '-tnp', 'state', 'established'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                remote = parts[4] if len(parts) > 4 else ''
                if ':' in remote:
                    port = int(remote.rsplit(':', 1)[-1]) if remote.rsplit(':', 1)[-1].isdigit() else 0
                    if port in suspicious_ports:
                        event = {
                            'event_type': 'network_connection',
                            'severity': 'high',
                            'description': f'Suspicious connection to port {port}: {remote}',
                            'destination_ip': remote.rsplit(':', 1)[0],
                            'destination_port': port,
                        }
                        send_event(config, event)
    except Exception as e:
        logger.debug(f"Network check error: {e}")


def check_failed_logins(config: dict):
    """Check for brute force attacks via failed login count."""
    try:
        result = subprocess.run(
            ['lastb', '-n', '10'],
            capture_output=True, text=True, timeout=5
        )
        count = len(result.stdout.strip().splitlines())
        if count >= 5:
            event = {
                'event_type': 'login_failed',
                'severity': 'critical',
                'description': f'Multiple failed login attempts detected ({count} in recent history)',
                'mitre_tactic': 'credential_access',
                'mitre_technique': 'T1110',
            }
            send_event(config, event)
    except Exception as e:
        logger.debug(f"Failed login check error: {e}")


def send_heartbeat(config: dict):
    """Send periodic heartbeat to update device last_seen."""
    req = urllib.request.Request(
        url=f"{config['server_url']}/cybershield/api/v1/health",
        method='GET'
    )
    try:
        with urllib.request.urlopen(req, timeout=5):
            logger.debug("Heartbeat sent")
    except Exception:
        pass


def main():
    logger.info(f"CyberShield Forwarder v{os.environ.get('CS_VERSION', '1.0.0')} started")

    try:
        config = load_config()
        logger.info(f"Device: {config['device_name']} | Server: {config['server_url']}")
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        sys.exit(1)

    cycle = 0
    while True:
        try:
            parse_auth_log(config)
            check_network_connections(config)

            if cycle % 10 == 0:  # Every 5 minutes
                check_failed_logins(config)
                send_heartbeat(config)

            cycle += 1
        except Exception as e:
            logger.error(f"Main loop error: {e}")

        time.sleep(config.get('poll_interval', 30))


if __name__ == '__main__':
    main()
PYEOF

    chmod +x "$CS_INSTALL_DIR/forwarder.py"
    chown "$CS_USER:$CS_USER" "$CS_INSTALL_DIR/forwarder.py"

    success "Forwarder daemon created"
}

# ── CREATE SYSTEMD SERVICE ─────────────────────────────────────────────────────
create_systemd_service() {
    log "Creating systemd service..."

    cat > "/etc/systemd/system/${CS_SERVICE_NAME}.service" << SVCEOF
[Unit]
Description=CyberShield Security Event Forwarder
Documentation=https://github.com/franjmenezz/cyber_shield
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$CS_USER
Group=$CS_USER
WorkingDirectory=$CS_INSTALL_DIR
ExecStart=/usr/bin/python3 $CS_INSTALL_DIR/forwarder.py
Restart=always
RestartSec=30
StandardOutput=append:$CS_LOG_DIR/forwarder.log
StandardError=append:$CS_LOG_DIR/forwarder.log
Environment="CS_VERSION=$CS_VERSION"

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$CS_LOG_DIR
ReadOnlyPaths=$CS_CONFIG_DIR $CS_INSTALL_DIR
CapabilityBoundingSet=
AmbientCapabilities=
SecureBits=noroot

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable "$CS_SERVICE_NAME"
    success "Systemd service created and enabled"
}

# ── REGISTER DEVICE WITH API ───────────────────────────────────────────────────
register_device() {
    log "Registering device with CyberShield server..."

    local response
    response=$(curl -sf \
        -H "X-CyberShield-Token: $AGENT_TOKEN" \
        -H "Content-Type: application/json" \
        "$SERVER_URL/cybershield/api/v1/device" 2>/dev/null) || true

    if echo "$response" | grep -q '"success":true' 2>/dev/null; then
        success "Device registered successfully"
    else
        warn "Could not reach CyberShield server — will retry when service starts"
    fi
}

# ── VERIFY INSTALLATION ────────────────────────────────────────────────────────
verify_installation() {
    log "Verifying installation..."
    local ok=true

    check_item() {
        if eval "$2" &>/dev/null; then
            success "✅ $1"
        else
            warn "❌ $1"
            ok=false
        fi
    }

    check_item "Config file"          "test -f $CS_CONFIG_DIR/config.json"
    check_item "Forwarder script"     "test -f $CS_INSTALL_DIR/forwarder.py"
    check_item "Log directory"        "test -d $CS_LOG_DIR"
    check_item "System user"          "id $CS_USER"
    check_item "Systemd service"      "systemctl is-enabled $CS_SERVICE_NAME"
    check_item "auditd running"       "systemctl is-active auditd"

    $ok && return 0 || return 1
}

# ── MAIN ───────────────────────────────────────────────────────────────────────
banner
[[ $EUID -ne 0 ]] && error "This script must be run as root or with sudo"
validate_inputs
check_deps
get_system_info
setup_directories
configure_auditd
install_wazuh
create_forwarder
create_systemd_service
register_device

if verify_installation; then
    systemctl start "$CS_SERVICE_NAME"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  CyberShield Agent installed successfully!        ${NC}"
    echo -e "${GREEN}  Device '${DEVICE_NAME}' is now protected.        ${NC}"
    echo -e "${GREEN}  Service: systemctl status ${CS_SERVICE_NAME}     ${NC}"
    echo -e "${GREEN}  Logs: tail -f ${CS_LOG_DIR}/forwarder.log        ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
    echo ""
else
    warn "Installation completed with warnings. Check: $CS_LOG_DIR/install.log"
fi
