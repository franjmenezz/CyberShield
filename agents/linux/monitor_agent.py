#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# CyberShield — Linux Monitoring Agent v2.0
# ==============================================================================
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.
#
# MONITORED EVENTS:
#   - Authentication (login, logout, sudo, SSH, screen lock)
#   - Processes (start, stop via /proc monitoring)
#   - File activity (open, create, modify, delete via inotify/auditd)
#   - Network connections (via /proc/net/tcp)
#   - USB devices (via udev)
#   - System events (boot, shutdown, package installs)
#   - Browser history (Chrome, Firefox)
#
# REQUIREMENTS: Python 3.8+, auditd, python3-pyinotify (optional)
# ==============================================================================

import hashlib
import hmac
import json
import logging
import os
import pwd
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path

CONFIG_PATH = "/etc/cybershield/config.json"
LOG_PATH    = "/var/log/cybershield/monitor.log"
STATE_PATH  = "/var/lib/cybershield/state.json"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("cybershield.monitor")


# ── CONFIG ────────────────────────────────────────────────────────────────────
def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def load_state():
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    if Path(STATE_PATH).exists():
        try:
            with open(STATE_PATH) as f:
                return json.load(f)
        except Exception:
            pass
    return {
        'last_auth_pos': 0,
        'last_audit_pos': 0,
        'last_processes': [],
        'last_usb': [],
        'last_packages': [],
        'last_browser_sync': None,
        'cycle': 0,
    }


def save_state(state):
    with open(STATE_PATH, 'w') as f:
        json.dump(state, f)


# ── API ───────────────────────────────────────────────────────────────────────
def send_events(config, events):
    if not events:
        return
    token = config['agent_token']
    url = f"{config['server_url']}/cybershield/api/v1/activity"

    # Batch in groups of 100
    for i in range(0, len(events), 100):
        batch = events[i:i+100]
        body = json.dumps(batch, ensure_ascii=True, separators=(',', ':'))
        sig = hmac.new(token.encode(), body.encode(), hashlib.sha256).hexdigest()

        req = urllib.request.Request(
            url, data=body.encode(), method='POST',
            headers={
                'Content-Type': 'application/json',
                'X-CyberShield-Token': token,
                'X-CyberShield-Signature': sig,
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
                log.debug(f"Sent {len(batch)} events: {result}")
        except Exception as e:
            log.error(f"Failed to send events: {e}")


# ── AUTH MONITORING ───────────────────────────────────────────────────────────
def get_auth_events(state):
    events = []
    auth_log = "/var/log/auth.log" if Path("/var/log/auth.log").exists() else "/var/log/secure"

    if not Path(auth_log).exists():
        return events, state['last_auth_pos']

    patterns = [
        (re.compile(r'Accepted (?:password|publickey) for (\S+) from ([\d.]+)'), 'login'),
        (re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.]+)'), 'login_failed'),
        (re.compile(r'session opened for user (\S+)'), 'login'),
        (re.compile(r'session closed for user (\S+)'), 'logout'),
        (re.compile(r'sudo:\s+(\S+)\s+:.*COMMAND=(.+)$'), 'process_create'),
        (re.compile(r'su\[\d+\]: \+ .* (\S+)-\>(\S+)'), 'login'),
    ]

    try:
        size = os.path.getsize(auth_log)
        pos = state.get('last_auth_pos', 0)
        if size < pos:
            pos = 0  # File rotated

        with open(auth_log, 'r', errors='ignore') as f:
            f.seek(pos)
            for line in f:
                for pattern, action in patterns:
                    m = pattern.search(line)
                    if m:
                        ev = {
                            'category': 'auth',
                            'action': action,
                            'os_user': m.group(1) if m.lastindex >= 1 else '',
                        }
                        if action != 'process_create' and m.lastindex >= 2:
                            ev['remote_ip'] = m.group(2)
                        if action == 'process_create':
                            ev['category'] = 'process'
                            ev['command_line'] = m.group(2) if m.lastindex >= 2 else ''
                        events.append(ev)
                        break
            pos = f.tell()
    except Exception as e:
        log.debug(f"Auth log error: {e}")

    return events, pos


# ── PROCESS MONITORING ────────────────────────────────────────────────────────
INTERESTING_APPS = {
    'chrome', 'chromium', 'firefox', 'brave', 'opera',
    'libreoffice', 'soffice', 'evince', 'gedit', 'vim', 'nano',
    'vscode', 'code', 'pycharm', 'intellij',
    'python', 'python3', 'node', 'java',
    'curl', 'wget', 'ssh', 'scp', 'rsync',
    'nmap', 'tcpdump', 'wireshark', 'netcat', 'nc',
    'zip', 'tar', 'gpg',
    'gimp', 'inkscape', 'blender',
    'slack', 'teams', 'zoom', 'skype',
    'thunderbird', 'evolution',
}

def get_current_processes():
    procs = set()
    try:
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            try:
                comm_path = f'/proc/{pid}/comm'
                if Path(comm_path).exists():
                    name = Path(comm_path).read_text().strip()
                    if name.lower() in INTERESTING_APPS or len(name) > 2:
                        procs.add(name)
            except Exception:
                pass
    except Exception:
        pass
    return procs


def get_process_events(state):
    events = []
    current = get_current_processes()
    last = set(state.get('last_processes', []))

    current_user = os.environ.get('USER', 'root')

    for app in current - last:
        events.append({
            'category': 'process',
            'action': 'app_start',
            'app_name': app,
            'os_user': current_user,
        })
    for app in last - current:
        events.append({
            'category': 'process',
            'action': 'app_stop',
            'app_name': app,
            'os_user': current_user,
        })

    return events, list(current)


# ── AUDITD FILE MONITORING ────────────────────────────────────────────────────
def get_file_events(state):
    events = []
    audit_log = "/var/log/audit/audit.log"

    if not Path(audit_log).exists():
        return events, state.get('last_audit_pos', 0)

    action_map = {
        'open': 'file_open', 'openat': 'file_open',
        'creat': 'file_create',
        'unlink': 'file_delete', 'unlinkat': 'file_delete',
        'rename': 'file_rename', 'renameat': 'file_rename',
        'write': 'file_modify',
    }

    try:
        size = os.path.getsize(audit_log)
        pos = state.get('last_audit_pos', 0)
        if size < pos:
            pos = 0

        with open(audit_log, 'r', errors='ignore') as f:
            f.seek(pos)
            for line in f:
                if 'cybershield' not in line.lower() and 'SYSCALL' in line:
                    syscall_m = re.search(r'syscall=(\w+)', line)
                    uid_m = re.search(r' uid=(\d+)', line)
                    path_m = re.search(r'name="([^"]+)"', line)

                    if syscall_m and path_m:
                        syscall = syscall_m.group(1)
                        action = action_map.get(syscall)
                        if action:
                            filepath = path_m.group(1)
                            # Skip noisy paths
                            if any(skip in filepath for skip in ['/proc/', '/sys/', '/dev/', '/run/']):
                                continue
                            uid = int(uid_m.group(1)) if uid_m else 0
                            try:
                                username = pwd.getpwuid(uid).pw_name
                            except Exception:
                                username = str(uid)
                            ext = Path(filepath).suffix.lstrip('.').lower()
                            events.append({
                                'category': 'file',
                                'action': action,
                                'file_path': filepath,
                                'file_extension': ext,
                                'os_user': username,
                            })
            pos = f.tell()
    except Exception as e:
        log.debug(f"Audit log error: {e}")

    return events, pos


# ── NETWORK MONITORING ────────────────────────────────────────────────────────
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 6697, 23, 1433, 5432}

def get_network_events():
    events = []
    try:
        result = subprocess.run(
            ['ss', '-tnp', 'state', 'established'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                remote = parts[4]
                if ':' in remote:
                    port_str = remote.rsplit(':', 1)[-1]
                    if port_str.isdigit():
                        port = int(port_str)
                        if port in SUSPICIOUS_PORTS:
                            ip = remote.rsplit(':', 1)[0]
                            events.append({
                                'category': 'network',
                                'action': 'net_connect',
                                'remote_ip': ip,
                                'remote_port': port,
                                'protocol': 'TCP',
                                'os_user': os.environ.get('USER', 'root'),
                            })
    except Exception as e:
        log.debug(f"Network monitor error: {e}")
    return events


# ── USB MONITORING ────────────────────────────────────────────────────────────
def get_usb_events(state):
    events = []
    current = []

    try:
        result = subprocess.run(
            ['lsblk', '-o', 'NAME,TRAN,VENDOR,MODEL,SERIAL', '--json'],
            capture_output=True, text=True, timeout=5
        )
        data = json.loads(result.stdout)
        for dev in data.get('blockdevices', []):
            if dev.get('tran') == 'usb':
                key = f"{dev.get('vendor','')}-{dev.get('model','')}-{dev.get('serial','')}"
                current.append(key)
    except Exception:
        pass

    last = state.get('last_usb', [])
    for dev in set(current) - set(last):
        parts = dev.split('-')
        events.append({
            'category': 'usb',
            'action': 'usb_connect',
            'usb_device_name': f"{parts[0]} {parts[1]}" if len(parts) >= 2 else dev,
            'usb_serial': parts[2] if len(parts) >= 3 else '',
            'os_user': os.environ.get('USER', 'root'),
        })
    for dev in set(last) - set(current):
        parts = dev.split('-')
        events.append({
            'category': 'usb',
            'action': 'usb_disconnect',
            'usb_device_name': f"{parts[0]} {parts[1]}" if len(parts) >= 2 else dev,
            'usb_serial': parts[2] if len(parts) >= 3 else '',
            'os_user': os.environ.get('USER', 'root'),
        })

    return events, current


# ── PACKAGE MONITORING ────────────────────────────────────────────────────────
def get_package_events(state):
    events = []
    pkg_log = None

    if Path('/var/log/dpkg.log').exists():
        pkg_log = '/var/log/dpkg.log'
    elif Path('/var/log/rpm/history.log').exists():
        pkg_log = '/var/log/rpm/history.log'

    if not pkg_log:
        return events, state.get('last_packages', [])

    installed = []
    try:
        with open(pkg_log, 'r', errors='ignore') as f:
            for line in f.readlines()[-50:]:  # Last 50 lines
                if 'install' in line.lower() or 'upgrade' in line.lower():
                    pkg_m = re.search(r'install\s+(\S+)', line)
                    if pkg_m:
                        pkg = pkg_m.group(1)
                        if pkg not in state.get('last_packages', []):
                            events.append({
                                'category': 'system',
                                'action': 'software_install',
                                'software_name': pkg,
                                'os_user': 'root',
                            })
                        installed.append(pkg)
    except Exception:
        pass

    return events, installed


# ── BROWSER HISTORY ───────────────────────────────────────────────────────────
def get_browser_events(state):
    events = []
    home = Path(os.path.expanduser('~'))
    cutoff = datetime.now() - timedelta(minutes=10)

    # Chrome/Chromium
    for browser_name, profile_path in [
        ('chrome', home / '.config/google-chrome/Default/History'),
        ('chromium', home / '.config/chromium/Default/History'),
        ('edge', home / '.config/microsoft-edge/Default/History'),
    ]:
        if profile_path.exists():
            if datetime.fromtimestamp(profile_path.stat().st_mtime) > cutoff:
                events.append({
                    'category': 'network',
                    'action': 'url_visit',
                    'browser': browser_name,
                    'domain': 'browser-activity',
                    'url': f'Browser active ({browser_name})',
                    'os_user': os.environ.get('USER', 'root'),
                })

    return events


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════
def main():
    log.info("CyberShield Monitor Agent v2.0 started (Linux)")

    config = load_config()
    state = load_state()
    log.info(f"Device: {config['device_name']} | Server: {config['server_url']}")

    while True:
        try:
            all_events = []
            cycle = state.get('cycle', 0)

            # Auth events (every cycle)
            auth_events, state['last_auth_pos'] = get_auth_events(state)
            all_events.extend(auth_events)

            # Process events (every cycle)
            proc_events, state['last_processes'] = get_process_events(state)
            all_events.extend(proc_events)

            # USB events (every cycle)
            usb_events, state['last_usb'] = get_usb_events(state)
            all_events.extend(usb_events)

            # File events via auditd (every cycle)
            file_events, state['last_audit_pos'] = get_file_events(state)
            all_events.extend(file_events)

            # Network (every 2 cycles)
            if cycle % 2 == 0:
                all_events.extend(get_network_events())

            # Browser (every 10 cycles)
            if cycle % 10 == 0:
                all_events.extend(get_browser_events(state))

            # Package installs (every 60 cycles)
            if cycle % 60 == 0:
                pkg_events, state['last_packages'] = get_package_events(state)
                all_events.extend(pkg_events)

            # Send
            if all_events:
                send_events(config, all_events)
                log.info(f"Cycle {cycle}: sent {len(all_events)} events")

            state['cycle'] = cycle + 1
            save_state(state)

        except Exception as e:
            log.error(f"Main loop error: {e}")

        time.sleep(config.get('poll_interval', 30))


if __name__ == '__main__':
    main()
