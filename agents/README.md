# CyberShield — Agent Installation Guide

> Copyright (c) 2025 Francisco José Jiménez Pozo — All rights reserved.

## Prerequisites

Before installing agents you need:
1. CyberShield module installed and running in ODOO
2. The device registered in **CyberShield → Configuration → Manage Devices**
3. The **Agent Token** for the device (CyberShield Admin only)
4. The **CyberShield Server URL** (e.g. `https://cybershield.yourcompany.com`)

---

## Windows Agent (install_agent.ps1)

### Requirements
- Windows 10/11 or Windows Server 2019/2022
- PowerShell 5.1+
- Run as Administrator

### Installation

```powershell
# Open PowerShell as Administrator
Set-ExecutionPolicy RemoteSigned -Scope Process

.\install_agent.ps1 `
  -ServerURL "https://cybershield.yourcompany.com" `
  -AgentToken "your-64-char-token-here" `
  -DeviceName "Diseño EQ1"
```

### With Wazuh Manager

```powershell
.\install_agent.ps1 `
  -ServerURL "https://cybershield.yourcompany.com" `
  -AgentToken "your-token-here" `
  -DeviceName "Contabilidad EQ1" `
  -WazuhManagerIP "10.0.0.10"
```

### What it installs
- Sysmon with CyberShield security rules
- CyberShield event forwarder (Windows Scheduled Task)
- Wazuh Agent (optional)

### Logs
`C:\ProgramData\CyberShield\logs\`

### Uninstall
```powershell
.\uninstall_agent.ps1
```

---

## Linux Agent (install_agent.sh)

### Requirements
- Ubuntu 20.04/22.04 LTS, Debian 11/12, or RHEL/CentOS 8/9
- Root or sudo access
- curl, python3

### Installation

```bash
sudo bash install_agent.sh \
  --server "https://cybershield.yourcompany.com" \
  --token  "your-64-char-token-here" \
  --name   "Servidor Web 01"
```

### With Wazuh Manager

```bash
sudo bash install_agent.sh \
  --server "https://cybershield.yourcompany.com" \
  --token  "your-token-here" \
  --name   "Servidor DB 01" \
  --wazuh  "10.0.0.10"
```

### What it installs
- auditd with CyberShield security rules
- CyberShield event forwarder (systemd service)
- Wazuh Agent (optional)

### Useful commands

```bash
# Check service status
sudo systemctl status cybershield-agent

# View logs
sudo tail -f /var/log/cybershield/forwarder.log

# Restart service
sudo systemctl restart cybershield-agent
```

### Uninstall

```bash
sudo bash uninstall_agent.sh
```

---

## Security Notes

- Agent tokens are unique per device and should never be shared
- All communication uses HMAC-SHA256 signatures
- TLS 1.3 is required in production
- Tokens can be regenerated from CyberShield → Configuration → Manage Devices

---

## Events Monitored

| Category | Windows | Linux |
|---|---|---|
| Login/Logout | ✅ Event 4624/4634 | ✅ auth.log |
| Failed logins | ✅ Event 4625 | ✅ auth.log + lastb |
| Privilege escalation | ✅ Event 4672 | ✅ sudo auditd |
| Process creation | ✅ Sysmon + 4688 | ✅ auditd execve |
| Network connections | ✅ Sysmon | ✅ ss connections |
| USB devices | ✅ Sysmon | ✅ udev events |
| Remote access | ✅ RDP sessions | ✅ SSH auth |
| File changes | ✅ Sysmon | ✅ auditd |
| User management | ✅ Events 4720/4726 | ✅ auditd useradd |
| Service changes | ✅ Events 7036/7040 | ✅ systemd |
