# Changelog — CyberShield

All notable changes to this project will be documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Wazuh Agent integration (Windows/Linux)
- VirusTotal API connector
- NVD/NIST CVE database integration
- Real-time Telegram/Email alerting
- Automated PDF report generation

---

## [1.0.0] - 2025-05-28

### Added
- Initial release of CyberShield for ODOO 18 Community
- `cyber.device` model — endpoint and server inventory
- `cyber.log` model — immutable activity log with HMAC-SHA256 integrity
- `cyber.alert` model — risk-classified security alerts (CRITICAL/HIGH/MEDIUM/LOW)
- `cyber.vulnerability` model — CVE tracking per asset
- `cyber.incident` model — full incident lifecycle management (ISO 27035 aligned)
- `cyber.report` model — audit report generation
- RBAC security with 5 granular access roles
- REST API endpoint with rate limiting, JWT auth and input validation
- Real-time security dashboard
- MITRE ATT&CK tactic/technique classification
- CVSS scoring for vulnerabilities
- Automatic incident creation on CRITICAL alerts
- Audit trail — immutable records with hash chaining
- Docker-based deployment support
- Wazuh Server integration foundation

### Security
- TLS 1.3 enforced for all API communications
- HMAC-SHA256 event signature verification
- Rate limiting: max 1000 events/min per agent
- Input sanitization on all API endpoints
- Zero Trust device authentication model

---

Copyright (c) 2025 Francisco José Jiménez Pozo — All rights reserved.
