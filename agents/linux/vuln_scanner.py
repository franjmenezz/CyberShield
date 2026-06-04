#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# CyberShield — Linux Vulnerability Scanner v1.0
# ==============================================================================
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.
#
# DESCRIPTION:
#   Scans installed packages and system configuration against the NVD (NIST)
#   CVE database and reports findings to the CyberShield API.
#
#   What it checks:
#     1. Installed packages (dpkg/rpm) vs NVD CVE database
#     2. Pending security updates (apt/yum)
#     3. Weak SSH configuration
#     4. Open ports and exposed services
#     5. World-writable files in sensitive paths
#     6. SUID/SGID binaries
#     7. Running services with known CVEs
#
# USAGE:
#   sudo python3 vuln_scanner.py \
#     --server "http://192.168.1.45:8069" \
#     --token  "your-token-here"
#
#   Or scheduled automatically by install_agent.sh (runs daily at 02:00)
# ==============================================================================

import argparse
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
CS_LOG_DIR   = "/var/log/cybershield"
CS_CACHE_DIR = "/var/cache/cybershield"
NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"

os.makedirs(CS_LOG_DIR, exist_ok=True)
os.makedirs(CS_CACHE_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f"{CS_LOG_DIR}/vuln_scanner.log"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("cybershield.vuln")


# ── ARGS ───────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="CyberShield Vulnerability Scanner")
    p.add_argument("--server", required=True, help="CyberShield server URL")
    p.add_argument("--token",  required=True, help="Agent token")
    return p.parse_args()


# ── HMAC + API ─────────────────────────────────────────────────────────────────
def sign(token: str, body: str) -> str:
    return hmac.new(token.encode(), body.encode(), hashlib.sha256).hexdigest()


def send_event(server_url: str, token: str, event: dict) -> bool:
    body = json.dumps(event, ensure_ascii=True, separators=(',', ':'))
    sig  = sign(token, body)
    req  = urllib.request.Request(
        url=f"{server_url}/cybershield/api/v1/event",
        data=body.encode(),
        headers={
            'Content-Type': 'application/json',
            'X-CyberShield-Token': token,
            'X-CyberShield-Signature': sig,
        },
        method='POST'
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            return result.get('success', False)
    except Exception as e:
        log.error(f"Failed to send event: {e}")
        return False


def send_vulnerability(server_url: str, token: str,
                       cve_id: str, name: str, component: str,
                       cvss_score: float, cvss_vector: str = "",
                       description: str = ""):
    severity = (
        "critical" if cvss_score >= 9.0 else
        "high"     if cvss_score >= 7.0 else
        "medium"   if cvss_score >= 4.0 else
        "low"
    )
    ok = send_event(server_url, token, {
        "event_type":    "other",
        "severity":      severity,
        "description":   f"VULNERABILITY: {cve_id} | {name} | Component: {component} | CVSS: {cvss_score} | {description}",
        "wazuh_rule_id": f"CS-VULN-{re.sub(r'[^A-Z0-9]', '-', cve_id)}",
        "mitre_tactic":  "discovery",
        "raw_data":      f"{cve_id}|{cvss_score}|{cvss_vector}",
    })
    if ok:
        log.info(f"Vulnerability reported: {cve_id} ({severity}, CVSS {cvss_score}) - {component}")
    return ok


# ── NVD API ────────────────────────────────────────────────────────────────────
def query_nvd(keyword: str) -> list:
    """Query NVD API with local cache (24h)."""
    cache_file = Path(CS_CACHE_DIR) / f"nvd_{re.sub(r'[^a-zA-Z0-9]', '_', keyword)}.json"

    # Return cache if fresh
    if cache_file.exists():
        age_hours = (time.time() - cache_file.stat().st_mtime) / 3600
        if age_hours < 24:
            try:
                return json.loads(cache_file.read_text()).get("vulnerabilities", [])
            except Exception:
                pass

    try:
        url = f"{NVD_API_URL}?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage=10"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            cache_file.write_text(json.dumps(data))
            time.sleep(0.7)  # NVD rate limit: 5 req/30s without API key
            return data.get("vulnerabilities", [])
    except Exception as e:
        log.warning(f"NVD API error for '{keyword}': {e}")
        return []


def get_cvss(vuln: dict) -> tuple:
    """Extract best available CVSS score and vector."""
    metrics = vuln.get("cve", {}).get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            return data.get("baseScore", 0.0), data.get("vectorString", "")
    return 0.0, ""


def get_cve_description(vuln: dict) -> str:
    try:
        descs = vuln.get("cve", {}).get("descriptions", [])
        for d in descs:
            if d.get("lang") == "en":
                text = d.get("value", "")
                return text[:300] + "..." if len(text) > 300 else text
    except Exception:
        pass
    return ""


# ══════════════════════════════════════════════════════════════════════════════
# 1. INSTALLED PACKAGES
# ══════════════════════════════════════════════════════════════════════════════
def get_installed_packages() -> list:
    """Get installed packages via dpkg or rpm."""
    packages = []

    # Debian/Ubuntu
    if shutil.which("dpkg"):
        try:
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.splitlines():
                parts = line.split('\t')
                if len(parts) >= 2 and parts[1]:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "arch": parts[2] if len(parts) > 2 else ""
                    })
        except Exception as e:
            log.warning(f"dpkg query error: {e}")

    # RHEL/CentOS
    elif shutil.which("rpm"):
        try:
            result = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.splitlines():
                parts = line.split('\t')
                if len(parts) >= 2:
                    packages.append({"name": parts[0], "version": parts[1], "arch": ""})
        except Exception as e:
            log.warning(f"rpm query error: {e}")

    log.info(f"Found {len(packages)} installed packages")
    return packages


# ══════════════════════════════════════════════════════════════════════════════
# 2. PENDING SECURITY UPDATES
# ══════════════════════════════════════════════════════════════════════════════
def check_pending_updates(server_url: str, token: str):
    """Check for pending security updates."""
    log.info("Checking pending security updates...")

    # apt-based systems
    if shutil.which("apt"):
        try:
            subprocess.run(["apt", "update", "-qq"], capture_output=True, timeout=60)
            result = subprocess.run(
                ["apt", "list", "--upgradable", "2>/dev/null"],
                capture_output=True, text=True, shell=False, timeout=30
            )
            upgradable = [l for l in result.stdout.splitlines() if l and "Listing" not in l]
            count = len(upgradable)

            if count > 0:
                # Check for security updates specifically
                sec_result = subprocess.run(
                    ["apt", "-s", "upgrade"],
                    capture_output=True, text=True, timeout=30
                )
                sec_count = len([l for l in sec_result.stdout.splitlines()
                                 if "security" in l.lower()])

                if sec_count > 0:
                    send_vulnerability(
                        server_url, token,
                        cve_id="LINUX-UPDATE-SECURITY",
                        name=f"{sec_count} security updates pending",
                        component="System Packages",
                        cvss_score=7.5,
                        description=f"{sec_count} security updates and {count-sec_count} other updates pending. Run: apt upgrade"
                    )
                else:
                    log.info(f"{count} updates pending (non-security)")
            else:
                log.info("System is up to date")
        except Exception as e:
            log.warning(f"apt update check error: {e}")

    # yum/dnf-based systems
    elif shutil.which("yum") or shutil.which("dnf"):
        pkg_mgr = "dnf" if shutil.which("dnf") else "yum"
        try:
            result = subprocess.run(
                [pkg_mgr, "check-update", "--security"],
                capture_output=True, text=True, timeout=60
            )
            # Return code 100 means updates available
            if result.returncode == 100:
                lines = [l for l in result.stdout.splitlines() if l and not l.startswith("Last")]
                send_vulnerability(
                    server_url, token,
                    cve_id="LINUX-UPDATE-SECURITY",
                    name=f"{len(lines)} security updates pending",
                    component="System Packages",
                    cvss_score=7.5,
                    description=f"{len(lines)} security updates pending. Run: {pkg_mgr} update --security"
                )
        except Exception as e:
            log.warning(f"{pkg_mgr} update check error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# 3. SSH CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════
def check_ssh_config(server_url: str, token: str):
    """Check SSH daemon configuration for weak settings."""
    log.info("Checking SSH configuration...")

    ssh_config = Path("/etc/ssh/sshd_config")
    if not ssh_config.exists():
        return

    try:
        config_text = ssh_config.read_text(errors='ignore')

        checks = [
            {
                "pattern": r"^PermitRootLogin\s+yes",
                "cve_id": "CONFIG-SSH-ROOT-LOGIN",
                "name": "SSH root login is permitted",
                "cvss": 8.1,
                "desc": "PermitRootLogin is set to 'yes'. Direct root login via SSH should be disabled."
            },
            {
                "pattern": r"^PasswordAuthentication\s+yes",
                "cve_id": "CONFIG-SSH-PASSWORD-AUTH",
                "name": "SSH password authentication enabled",
                "cvss": 5.9,
                "desc": "PasswordAuthentication is enabled. Key-based authentication is more secure."
            },
            {
                "pattern": r"^X11Forwarding\s+yes",
                "cve_id": "CONFIG-SSH-X11",
                "name": "SSH X11 forwarding enabled",
                "cvss": 4.3,
                "desc": "X11Forwarding is enabled. This may expose local display to remote users."
            },
            {
                "pattern": r"^Protocol\s+1",
                "cve_id": "CONFIG-SSH-PROTO1",
                "name": "SSH Protocol 1 enabled (deprecated)",
                "cvss": 9.1,
                "desc": "SSH Protocol 1 is enabled. Protocol 1 has known cryptographic vulnerabilities."
            },
        ]

        for check in checks:
            if re.search(check["pattern"], config_text, re.MULTILINE | re.IGNORECASE):
                send_vulnerability(
                    server_url, token,
                    cve_id=check["cve_id"],
                    name=check["name"],
                    component="SSH Daemon (sshd)",
                    cvss_score=check["cvss"],
                    description=check["desc"]
                )

        # Check if port 22 is the default (minor risk, informational)
        if not re.search(r"^Port\s+(?!22\b)", config_text, re.MULTILINE):
            log.info("SSH running on default port 22 (informational)")

    except Exception as e:
        log.warning(f"SSH config check error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# 4. OPEN PORTS / EXPOSED SERVICES
# ══════════════════════════════════════════════════════════════════════════════
def check_open_ports(server_url: str, token: str):
    """Check for dangerous open ports."""
    log.info("Checking open ports...")

    risky_ports = {
        23:    ("Telnet", 9.8, "Telnet transmits data in cleartext including passwords."),
        21:    ("FTP", 7.5, "FTP transmits credentials in cleartext."),
        512:   ("rexec", 9.8, "Remote exec service — severe security risk."),
        513:   ("rlogin", 9.8, "Remote login — no encryption, severe risk."),
        514:   ("rsh", 9.8, "Remote shell — no authentication required."),
        1433:  ("MSSQL", 7.5, "Microsoft SQL Server exposed to network."),
        3306:  ("MySQL", 7.5, "MySQL/MariaDB exposed to network."),
        5432:  ("PostgreSQL", 7.5, "PostgreSQL exposed to network."),
        6379:  ("Redis", 9.8, "Redis often has no authentication by default."),
        27017: ("MongoDB", 9.8, "MongoDB may have no authentication by default."),
        9200:  ("Elasticsearch", 9.8, "Elasticsearch may expose sensitive data without auth."),
        2375:  ("Docker API", 10.0, "Docker daemon API exposed — full container/host control."),
        2379:  ("etcd", 9.8, "etcd exposed — Kubernetes secrets at risk."),
    }

    try:
        result = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                local = parts[3]
                port_str = local.rsplit(':', 1)[-1] if ':' in local else ''
                if port_str.isdigit():
                    port = int(port_str)
                    if port in risky_ports:
                        svc, cvss, desc = risky_ports[port]
                        send_vulnerability(
                            server_url, token,
                            cve_id=f"CONFIG-PORT-{port}",
                            name=f"{svc} service exposed on port {port}",
                            component=svc,
                            cvss_score=cvss,
                            description=desc
                        )
    except Exception as e:
        log.warning(f"Port check error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# 5. SUID/SGID BINARIES
# ══════════════════════════════════════════════════════════════════════════════
def check_suid_binaries(server_url: str, token: str):
    """Check for unexpected SUID/SGID binaries."""
    log.info("Checking SUID/SGID binaries...")

    known_suid = {
        '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/passwd',
        '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/newgrp',
        '/usr/bin/gpasswd', '/usr/bin/mount', '/usr/bin/umount',
        '/usr/sbin/pppd', '/bin/ping', '/bin/su', '/bin/mount',
        '/bin/umount', '/usr/bin/pkexec',
    }

    try:
        result = subprocess.run(
            ["find", "/", "-xdev", "-type", "f",
             "-perm", "/6000", "-not", "-path", "/proc/*"],
            capture_output=True, text=True, timeout=60
        )
        found_suid = set(result.stdout.strip().splitlines())
        unexpected = found_suid - known_suid

        if unexpected:
            for binary in list(unexpected)[:10]:  # Report max 10
                send_vulnerability(
                    server_url, token,
                    cve_id="CONFIG-SUID-UNEXPECTED",
                    name=f"Unexpected SUID/SGID binary: {binary}",
                    component="File System",
                    cvss_score=7.8,
                    description=f"Unexpected SUID/SGID binary found: {binary}. May be exploitable for privilege escalation."
                )
    except Exception as e:
        log.warning(f"SUID check error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# 6. WORLD-WRITABLE FILES
# ══════════════════════════════════════════════════════════════════════════════
def check_world_writable(server_url: str, token: str):
    """Check for world-writable files in sensitive paths."""
    log.info("Checking world-writable files...")

    sensitive_paths = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]

    for path in sensitive_paths:
        if not Path(path).exists():
            continue
        try:
            result = subprocess.run(
                ["find", path, "-xdev", "-type", "f", "-perm", "-0002"],
                capture_output=True, text=True, timeout=30
            )
            files = [f for f in result.stdout.strip().splitlines() if f]
            if files:
                send_vulnerability(
                    server_url, token,
                    cve_id="CONFIG-WORLD-WRITABLE",
                    name=f"{len(files)} world-writable files in {path}",
                    component="File System",
                    cvss_score=7.5,
                    description=f"World-writable files found in {path}: {', '.join(files[:3])}{'...' if len(files) > 3 else ''}"
                )
        except Exception as e:
            log.debug(f"World-writable check error in {path}: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# 7. SCAN PACKAGES AGAINST NVD
# ══════════════════════════════════════════════════════════════════════════════
# High-priority packages to check against NVD
PRIORITY_PACKAGES = {
    "openssl", "openssh", "openssh-server", "openssh-client",
    "apache2", "nginx", "lighttpd",
    "php", "php-common", "php-cli",
    "mysql-server", "mariadb-server", "postgresql",
    "python3", "python3-pip",
    "nodejs", "npm",
    "docker", "docker.io", "docker-ce",
    "samba", "nfs-kernel-server",
    "bind9", "named",
    "postfix", "dovecot",
    "wordpress", "joomla",
    "sudo", "curl", "wget",
    "libssl", "libc6", "glibc",
    "kernel", "linux-image",
}


def scan_packages_nvd(server_url: str, token: str, packages: list) -> int:
    """Scan installed packages against NVD CVE database."""
    log.info("Scanning packages against NVD CVE database...")

    priority = [p for p in packages
                if any(name in p["name"].lower() for name in PRIORITY_PACKAGES)]

    log.info(f"Scanning {len(priority)} priority packages out of {len(packages)} total")

    vuln_count = 0
    for i, pkg in enumerate(priority):
        name = pkg["name"]
        version = pkg["version"]

        vulns = query_nvd(name)
        for vuln in vulns:
            cve_id = vuln.get("cve", {}).get("id", "UNKNOWN")
            score, vector = get_cvss(vuln)
            if score < 4.0:
                continue
            desc = get_cve_description(vuln)

            send_vulnerability(
                server_url, token,
                cve_id=cve_id,
                name=f"{cve_id} in {name} {version}",
                component=f"{name} {version}",
                cvss_score=score,
                cvss_vector=vector,
                description=desc
            )
            vuln_count += 1

        # Rate limiting: 4 requests per 30s (safe margin)
        if (i + 1) % 4 == 0:
            log.info(f"Rate limit pause ({i+1}/{len(priority)} scanned)...")
            time.sleep(30)

    log.info(f"NVD scan complete: {vuln_count} vulnerabilities found")
    return vuln_count


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    args = parse_args()
    server_url = args.server.rstrip('/')
    token = args.token

    log.info("═" * 55)
    log.info("CyberShield Vulnerability Scanner v1.0 — Linux")
    log.info(f"Server: {server_url}")
    log.info("═" * 55)

    # Send scan start
    send_event(server_url, token, {
        "event_type": "other",
        "severity": "info",
        "description": f"CyberShield vulnerability scan started on {os.uname().nodename}",
        "wazuh_rule_id": "CS-VULN-SCAN-START",
    })

    total_vulns = 0

    # Run all checks
    packages = get_installed_packages()
    check_pending_updates(server_url, token)
    check_ssh_config(server_url, token)
    check_open_ports(server_url, token)
    check_suid_binaries(server_url, token)
    check_world_writable(server_url, token)
    total_vulns += scan_packages_nvd(server_url, token, packages)

    # Send scan complete
    send_event(server_url, token, {
        "event_type": "other",
        "severity": "info",
        "description": f"CyberShield vulnerability scan completed — {total_vulns} vulnerabilities reported",
        "wazuh_rule_id": "CS-VULN-SCAN-END",
    })

    log.info("═" * 55)
    log.info(f"Scan complete — {total_vulns} vulnerabilities found")
    log.info("═" * 55)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root (sudo)")
        sys.exit(1)
    main()
