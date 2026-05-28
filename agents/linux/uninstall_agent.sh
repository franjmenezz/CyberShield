#!/bin/bash
# ==============================================================================
# CyberShield — Linux Agent Uninstaller
# Copyright (c) 2025 Francisco José Jiménez Pozo — All rights reserved.
# ==============================================================================
set -euo pipefail
[[ $EUID -ne 0 ]] && echo "Run as root" && exit 1

CS_SERVICE="cybershield-agent"
echo "[CyberShield] Uninstalling agent..."

systemctl stop "$CS_SERVICE" 2>/dev/null || true
systemctl disable "$CS_SERVICE" 2>/dev/null || true
rm -f "/etc/systemd/system/${CS_SERVICE}.service"
systemctl daemon-reload
rm -f /etc/audit/rules.d/cybershield.rules
augenrules --load 2>/dev/null || true
rm -rf /opt/cybershield /etc/cybershield
userdel cybershield 2>/dev/null || true

echo "[CyberShield] Agent uninstalled successfully."
