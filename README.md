<div align="center">

# 🛡️ CyberShield

### Enterprise Security Information & Event Management for ODOO 18

[![ODOO](https://img.shields.io/badge/ODOO-18.0_Community-714B67?style=for-the-badge&logo=odoo&logoColor=white)](https://www.odoo.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=for-the-badge)](./LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge)](./CHANGELOG.md)
[![Security](https://img.shields.io/badge/Security-ISO_27001_%7C_NIST_CSF_2.0-green?style=for-the-badge)](./SECURITY.md)
[![MITRE](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-orange?style=for-the-badge)](https://attack.mitre.org)

---

**CyberShield** is a native SIEM module for ODOO 18 Community that provides
real-time endpoint monitoring, threat detection, vulnerability management,
and incident response — fully integrated into your ODOO environment.

[📖 Documentation](#documentation) · [🚀 Installation](#installation) · [🔐 Security](#security) · [📞 Contact](#contact)

</div>

---

## ✨ Features

| Feature | Description |
|---|---|
| 📊 **Real-time Dashboard** | Live overview of your security posture |
| 💻 **Endpoint Monitoring** | Agents on every PC and server (Windows & Linux) |
| 📋 **Immutable Audit Log** | HMAC-SHA256 signed, tamper-proof event records |
| 🚨 **Smart Alerting** | CRITICAL / HIGH / MEDIUM / LOW risk classification |
| 🔓 **Vulnerability Management** | CVE tracking with CVSS scoring per asset |
| 🔥 **Incident Management** | Full lifecycle aligned with ISO 27035 |
| 🗂️ **IT Asset Inventory** | Complete hardware and software inventory |
| 📁 **Audit Reports** | Automated PDF report generation |
| 🔗 **Wazuh Integration** | Enterprise-grade endpoint telemetry |
| 🎯 **MITRE ATT&CK** | Tactics and techniques classification |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ENDPOINTS                             │
│  [Windows PCs]          [Linux Servers]                  │
│  Wazuh Agent + Sysmon   Wazuh Agent + Auditd            │
└──────────────────────┬──────────────────────────────────┘
                       │ TLS 1.3 + Mutual Auth
                       ▼
┌─────────────────────────────────────────────────────────┐
│              WAZUH SERVER                                │
│  Manager → Analyzer → Correlator → OpenSearch           │
│                    REST API (JWT)                        │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTPS + HMAC-SHA256
                       ▼
┌─────────────────────────────────────────────────────────┐
│           CYBERSHIELD — ODOO 18                          │
│                                                          │
│  Dashboard · Devices · Logs · Alerts                    │
│  Vulnerabilities · Incidents · Reports                  │
└─────────────────────────────────────────────────────────┘
```

---

## 📋 Requirements

### ODOO Server
- ODOO 18.0 Community Edition
- Python 3.10+
- PostgreSQL 15+

### Infrastructure
- Wazuh Server 4.x (Docker recommended)
- Ubuntu Server 22.04 LTS (recommended)
- Minimum 4GB RAM / 2 vCPU for ODOO + CyberShield
- Minimum 8GB RAM / 4 vCPU including Wazuh Server

### Endpoint Agents
- Windows 10/11 — Wazuh Agent + Sysmon
- Linux (Debian/Ubuntu/RHEL) — Wazuh Agent + Auditd

---

## 🚀 Installation

> ⚠️ **Authorized use only.** See [LICENSE](./LICENSE) before proceeding.

### 1. Clone the repository (authorized users only)

```bash
git clone https://github.com/franjmenezz/cyber_shield.git
cd cyber_shield
```

### 2. Copy module to ODOO addons

```bash
cp -r cyber_shield /path/to/odoo/addons/
```

### 3. Update ODOO module list

```bash
python odoo-bin -u cyber_shield -d your_database
```

### 4. Install from ODOO Apps

Go to **Apps → Remove "Apps" filter → Search "CyberShield" → Install**

### 5. Configure API credentials

Go to **CyberShield → Configuration → Settings**

For full deployment instructions, see [Installation Manual](./docs/admin/installation.md).

---

## 🔐 Security

CyberShield is built with **Security by Design** principles:

- **Zero Trust** — every device authenticates independently
- **TLS 1.3** — enforced for all communications
- **HMAC-SHA256** — event integrity verification
- **RBAC** — 5 granular access roles
- **Immutable Logs** — tamper-proof audit trail
- **Rate Limiting** — anti-flood protection (1000 events/min/agent)
- **Input Validation** — strict sanitization on all endpoints
- **OWASP Top 10** — compliance verified

Standards alignment:
- ISO/IEC 27001:2022
- NIST Cybersecurity Framework 2.0
- MITRE ATT&CK
- ISO/IEC 27035 (Incident Management)

To report a security vulnerability, see [SECURITY.md](./SECURITY.md).

---

## 📚 Documentation

| Document | Description |
|---|---|
| [User Manual](./docs/user/user_manual.md) | End-user guide |
| [Admin Manual](./docs/admin/admin_manual.md) | Administrator guide |
| [Installation Guide](./docs/admin/installation.md) | Deployment instructions |
| [API Reference](./docs/technical/api_reference.md) | REST API documentation |
| [Architecture](./docs/technical/architecture.md) | Technical design |
| [SRS](./docs/reports/SRS.md) | Software Requirements Specification |
| [SDD](./docs/reports/SDD.md) | Software Design Document |

---

## 🗺️ Roadmap

- [x] Core module structure
- [x] Device & server inventory
- [x] Immutable audit logs
- [x] Alert classification engine
- [x] Vulnerability management
- [x] Incident lifecycle management
- [x] RBAC security model
- [x] REST API endpoint
- [ ] Wazuh Agent scripts (Windows/Linux)
- [ ] VirusTotal integration
- [ ] NVD/NIST CVE database sync
- [ ] Telegram/Email real-time alerts
- [ ] Automated PDF report generation
- [ ] ODOO 18 dashboard widgets
- [ ] Multi-company support

---

## 📄 License

**CyberShield** is proprietary software.
Copyright (c) 2025 Francisco José Jiménez Pozo. All rights reserved.

Unauthorized use, copying, or distribution is strictly prohibited.
See [LICENSE](./LICENSE) for full terms.

---

## 📞 Contact

**Francisco José Jiménez Pozo**
- 📧 Email: [fjjpozo075@gmail.com](mailto:fjjpozo075@gmail.com)
- 🐙 GitHub: [@franjmenezz](https://github.com/franjmenezz)

---

<div align="center">

Made with ❤️ by **Francisco José Jiménez Pozo**

*DevSecOps Engineer · ODOO Developer · Cybersecurity Specialist*

</div>
