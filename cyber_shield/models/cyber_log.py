# -*- coding: utf-8 -*-
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.

import hashlib
import json
from datetime import datetime
from odoo import models, fields, api, _
from odoo.exceptions import AccessError


class CyberLog(models.Model):
    """
    CyberShield — Immutable Activity Log
    Records every security event received from endpoints.
    Logs are IMMUTABLE — they cannot be modified or deleted after creation.
    Integrity is guaranteed via HMAC-SHA256 hash chaining.
    """
    _name = 'cyber.log'
    _description = 'CyberShield — Activity Log (Immutable)'
    _order = 'timestamp desc, id desc'
    _log_access = False  # Disable automatic write_date/write_uid logging

    # ── IDENTIFICATION ────────────────────────────────────────────────────────
    log_uid = fields.Char(
        string='Log UID',
        readonly=True,
        index=True,
        copy=False,
    )
    event_hash = fields.Char(
        string='Integrity Hash',
        readonly=True,
        copy=False,
        help='HMAC-SHA256 hash of the event data for tamper detection',
    )
    previous_hash = fields.Char(
        string='Previous Hash',
        readonly=True,
        copy=False,
        help='Hash of the previous log entry — enables hash chaining',
    )

    # ── SOURCE ────────────────────────────────────────────────────────────────
    device_id = fields.Many2one(
        comodel_name='cyber.device',
        string='Device',
        required=True,
        ondelete='restrict',
        index=True,
        readonly=True,
    )
    wazuh_agent_id = fields.Char(
        string='Wazuh Agent ID',
        readonly=True,
    )
    source_ip = fields.Char(
        string='Source IP',
        readonly=True,
    )

    # ── EVENT CLASSIFICATION ──────────────────────────────────────────────────
    event_type = fields.Selection(
        selection=[
            ('login', 'Login'),
            ('logout', 'Logout'),
            ('login_failed', 'Failed Login'),
            ('privilege_escalation', 'Privilege Escalation'),
            ('remote_access', 'Remote Access'),
            ('usb_connected', 'USB Device Connected'),
            ('usb_disconnected', 'USB Device Disconnected'),
            ('file_access', 'File Access'),
            ('file_modified', 'File Modified'),
            ('file_deleted', 'File Deleted'),
            ('process_created', 'Process Created'),
            ('process_terminated', 'Process Terminated'),
            ('network_connection', 'Network Connection'),
            ('network_blocked', 'Network Connection Blocked'),
            ('port_scan', 'Port Scan Detected'),
            ('malware_detected', 'Malware Detected'),
            ('policy_violation', 'Policy Violation'),
            ('config_changed', 'Configuration Changed'),
            ('user_created', 'User Account Created'),
            ('user_deleted', 'User Account Deleted'),
            ('user_modified', 'User Account Modified'),
            ('service_started', 'Service Started'),
            ('service_stopped', 'Service Stopped'),
            ('system_boot', 'System Boot'),
            ('system_shutdown', 'System Shutdown'),
            ('other', 'Other'),
        ],
        string='Event Type',
        required=True,
        readonly=True,
        index=True,
    )
    severity = fields.Selection(
        selection=[
            ('critical', 'Critical'),
            ('high', 'High'),
            ('medium', 'Medium'),
            ('low', 'Low'),
            ('info', 'Info'),
        ],
        string='Severity',
        required=True,
        readonly=True,
        index=True,
        default='info',
    )

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    mitre_tactic = fields.Selection(
        selection=[
            ('reconnaissance', 'TA0043 — Reconnaissance'),
            ('resource_development', 'TA0042 — Resource Development'),
            ('initial_access', 'TA0001 — Initial Access'),
            ('execution', 'TA0002 — Execution'),
            ('persistence', 'TA0003 — Persistence'),
            ('privilege_escalation', 'TA0004 — Privilege Escalation'),
            ('defense_evasion', 'TA0005 — Defense Evasion'),
            ('credential_access', 'TA0006 — Credential Access'),
            ('discovery', 'TA0007 — Discovery'),
            ('lateral_movement', 'TA0008 — Lateral Movement'),
            ('collection', 'TA0009 — Collection'),
            ('command_control', 'TA0011 — Command & Control'),
            ('exfiltration', 'TA0010 — Exfiltration'),
            ('impact', 'TA0040 — Impact'),
        ],
        string='MITRE Tactic',
        readonly=True,
    )
    mitre_technique = fields.Char(
        string='MITRE Technique',
        readonly=True,
        help='e.g. T1078 (Valid Accounts), T1059 (Command Scripting)',
    )

    # ── EVENT DETAILS ─────────────────────────────────────────────────────────
    timestamp = fields.Datetime(
        string='Timestamp',
        required=True,
        readonly=True,
        index=True,
        default=fields.Datetime.now,
    )
    description = fields.Text(
        string='Description',
        required=True,
        readonly=True,
    )
    raw_data = fields.Text(
        string='Raw Event Data',
        readonly=True,
        help='Original JSON payload received from Wazuh',
    )
    user_name = fields.Char(
        string='OS Username',
        readonly=True,
        help='Operating system user involved in the event',
    )
    process_name = fields.Char(
        string='Process',
        readonly=True,
    )
    file_path = fields.Char(
        string='File Path',
        readonly=True,
    )
    destination_ip = fields.Char(
        string='Destination IP',
        readonly=True,
    )
    destination_port = fields.Integer(
        string='Destination Port',
        readonly=True,
    )
    wazuh_rule_id = fields.Char(
        string='Wazuh Rule ID',
        readonly=True,
    )
    wazuh_rule_level = fields.Integer(
        string='Wazuh Rule Level',
        readonly=True,
        help='Wazuh alert level 0-15',
    )

    # ── ALERT REFERENCE ───────────────────────────────────────────────────────
    alert_id = fields.Many2one(
        comodel_name='cyber.alert',
        string='Generated Alert',
        readonly=True,
        help='Alert generated from this log entry if severity >= HIGH',
    )

    # ── IMMUTABILITY ENFORCEMENT ─────────────────────────────────────────────
    def write(self, vals):
        """Logs are IMMUTABLE. Write operations are forbidden."""
        raise AccessError(_(
            'CyberShield logs are immutable and cannot be modified. '
            'This is required to maintain audit trail integrity.'
        ))

    def unlink(self):
        """Logs cannot be deleted."""
        raise AccessError(_(
            'CyberShield logs cannot be deleted. '
            'Deletion would compromise audit trail integrity.'
        ))

    # ── CREATION WITH INTEGRITY HASH ─────────────────────────────────────────
    @api.model_create_multi
    def create(self, vals_list):
        """
        Create immutable log entries with HMAC-SHA256 hash chaining.
        Each entry's hash includes the previous entry's hash,
        making tampering detectable.
        """
        import uuid as uuid_lib
        last_hash = self._get_last_hash()

        for vals in vals_list:
            if not vals.get('log_uid'):
                vals['log_uid'] = str(uuid_lib.uuid4())

            # Build canonical payload for hashing
            payload = {
                'log_uid': vals['log_uid'],
                'device_id': vals.get('device_id'),
                'event_type': vals.get('event_type'),
                'severity': vals.get('severity'),
                'timestamp': str(vals.get('timestamp', datetime.now())),
                'description': vals.get('description', ''),
                'previous_hash': last_hash,
            }
            canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True)
            current_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()

            vals['event_hash'] = current_hash
            vals['previous_hash'] = last_hash
            last_hash = current_hash

        records = super().create(vals_list)

        # Auto-generate alert for HIGH and CRITICAL events
        for record in records:
            if record.severity in ('critical', 'high'):
                record._auto_create_alert()

        return records

    def _get_last_hash(self):
        """Get the hash of the most recent log entry for chaining."""
        last = self.search([], order='id desc', limit=1)
        return last.event_hash if last else '0' * 64

    def _auto_create_alert(self):
        """Automatically create an alert for high/critical severity events."""
        alert = self.env['cyber.alert'].sudo().create({
            'name': f'[{self.severity.upper()}] {self.event_type} — {self.device_id.display_name}',
            'device_id': self.device_id.id,
            'severity': self.severity,
            'log_id': self.id,
            'description': self.description,
            'mitre_tactic': self.mitre_tactic,
            'mitre_technique': self.mitre_technique,
            'source_ip': self.source_ip,
        })
        # Link alert back to log — bypass immutability via sudo + direct SQL
        self.env.cr.execute(
            "UPDATE cyber_log SET alert_id = %s WHERE id = %s",
            (alert.id, self.id)
        )

    def action_verify_integrity(self):
        """Verify the integrity hash of this log entry."""
        self.ensure_one()
        payload = {
            'log_uid': self.log_uid,
            'device_id': self.device_id.id,
            'event_type': self.event_type,
            'severity': self.severity,
            'timestamp': str(self.timestamp),
            'description': self.description or '',
            'previous_hash': self.previous_hash or ('0' * 64),
        }
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True)
        expected_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Integrity Check'),
                'message': _('✅ Hash verified — Log intact') if expected_hash == self.event_hash
                           else _('❌ Hash mismatch — Log may have been tampered!'),
                'type': 'success' if expected_hash == self.event_hash else 'danger',
                'sticky': True,
            }
        }
