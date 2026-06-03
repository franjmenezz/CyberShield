# -*- coding: utf-8 -*-
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.

"""
CyberShield — Device Activity Model
=====================================
Records detailed activity from monitored endpoints:
  - Process execution (applications used)
  - File access (documents opened/modified)
  - Network connections (URLs visited, IPs contacted)
  - USB devices connected/disconnected
  - System events (login, logout, boot, shutdown)
  - Browser activity (URLs visited per browser)
  - Active window / application focus

All records are immutable after creation.
"""

import hashlib
import json
import logging
from odoo import models, fields, api, _
from odoo.exceptions import AccessError

_logger = logging.getLogger(__name__)


class CyberActivity(models.Model):
    """
    CyberShield — Device Activity Record
    Detailed activity log per device — immutable after creation.
    """
    _name = 'cyber.activity'
    _description = 'CyberShield — Device Activity'
    _order = 'timestamp desc, id desc'
    _log_access = False

    # ── IDENTIFICATION ────────────────────────────────────────────────────────
    device_id = fields.Many2one(
        comodel_name='cyber.device',
        string='Device',
        required=True,
        ondelete='restrict',
        index=True,
        readonly=True,
    )
    timestamp = fields.Datetime(
        string='Timestamp',
        required=True,
        readonly=True,
        index=True,
        default=fields.Datetime.now,
    )

    # ── CATEGORY ──────────────────────────────────────────────────────────────
    category = fields.Selection(
        selection=[
            ('auth',      '🔐 Authentication'),
            ('process',   '⚙️  Process / Application'),
            ('file',      '📄 File Activity'),
            ('network',   '🌐 Network / Web'),
            ('usb',       '🔌 USB Device'),
            ('system',    '💻 System Event'),
            ('print',     '🖨️  Print Job'),
            ('clipboard', '📋 Clipboard'),
        ],
        string='Category',
        required=True,
        readonly=True,
        index=True,
    )
    action = fields.Selection(
        selection=[
            # Auth
            ('login',              'Login'),
            ('logout',             'Logout'),
            ('login_failed',       'Failed Login'),
            ('lock',               'Screen Locked'),
            ('unlock',             'Screen Unlocked'),
            ('rdp_connect',        'RDP Connected'),
            ('rdp_disconnect',     'RDP Disconnected'),
            # Process
            ('app_start',          'Application Started'),
            ('app_stop',           'Application Stopped'),
            ('app_focus',          'Application Focused'),
            ('process_create',     'Process Created'),
            # File
            ('file_open',          'File Opened'),
            ('file_create',        'File Created'),
            ('file_modify',        'File Modified'),
            ('file_delete',        'File Deleted'),
            ('file_rename',        'File Renamed'),
            ('file_copy',          'File Copied'),
            ('file_move',          'File Moved'),
            # Network / Web
            ('url_visit',          'URL Visited'),
            ('net_connect',        'Network Connection'),
            ('net_blocked',        'Connection Blocked'),
            ('dns_query',          'DNS Query'),
            # USB
            ('usb_connect',        'USB Connected'),
            ('usb_disconnect',     'USB Disconnected'),
            ('usb_file_copy',      'File Copied to USB'),
            # System
            ('boot',               'System Boot'),
            ('shutdown',           'System Shutdown'),
            ('sleep',              'System Sleep'),
            ('wake',               'System Wake'),
            ('update_install',     'Update Installed'),
            ('software_install',   'Software Installed'),
            ('software_uninstall', 'Software Uninstalled'),
            # Print
            ('print_job',          'Print Job'),
            # Clipboard
            ('clipboard_copy',     'Clipboard Copy'),
        ],
        string='Action',
        required=True,
        readonly=True,
        index=True,
    )

    # ── USER ──────────────────────────────────────────────────────────────────
    os_user = fields.Char(
        string='OS User',
        readonly=True,
        index=True,
        help='Operating system username performing the action',
    )

    # ── PROCESS / APPLICATION ─────────────────────────────────────────────────
    app_name = fields.Char(
        string='Application',
        readonly=True,
        help='Application or process name (e.g. chrome.exe, Word, python.exe)',
    )
    app_path = fields.Char(
        string='Application Path',
        readonly=True,
    )
    process_id = fields.Integer(
        string='PID',
        readonly=True,
    )
    parent_process = fields.Char(
        string='Parent Process',
        readonly=True,
    )
    command_line = fields.Char(
        string='Command Line',
        readonly=True,
    )

    # ── FILE ──────────────────────────────────────────────────────────────────
    file_path = fields.Char(
        string='File Path',
        readonly=True,
    )
    file_name = fields.Char(
        string='File Name',
        compute='_compute_file_name',
        store=True,
    )
    file_extension = fields.Char(
        string='Extension',
        compute='_compute_file_name',
        store=True,
    )
    file_size = fields.Integer(
        string='File Size (bytes)',
        readonly=True,
    )
    destination_path = fields.Char(
        string='Destination Path',
        readonly=True,
        help='For rename/copy/move operations',
    )

    # ── NETWORK / WEB ─────────────────────────────────────────────────────────
    url = fields.Char(
        string='URL',
        readonly=True,
    )
    domain = fields.Char(
        string='Domain',
        compute='_compute_domain',
        store=True,
    )
    browser = fields.Selection(
        selection=[
            ('chrome',  'Google Chrome'),
            ('firefox', 'Mozilla Firefox'),
            ('edge',    'Microsoft Edge'),
            ('safari',  'Safari'),
            ('other',   'Other'),
        ],
        string='Browser',
        readonly=True,
    )
    remote_ip = fields.Char(string='Remote IP', readonly=True)
    remote_port = fields.Integer(string='Remote Port', readonly=True)
    local_port = fields.Integer(string='Local Port', readonly=True)
    protocol = fields.Char(string='Protocol', readonly=True)
    bytes_sent = fields.Integer(string='Bytes Sent', readonly=True)
    bytes_recv = fields.Integer(string='Bytes Received', readonly=True)

    # ── USB ───────────────────────────────────────────────────────────────────
    usb_device_name = fields.Char(string='USB Device Name', readonly=True)
    usb_serial = fields.Char(string='USB Serial Number', readonly=True)
    usb_drive_letter = fields.Char(string='Drive Letter', readonly=True)

    # ── SYSTEM ────────────────────────────────────────────────────────────────
    software_name = fields.Char(string='Software Name', readonly=True)
    software_version = fields.Char(string='Software Version', readonly=True)

    # ── PRINT ─────────────────────────────────────────────────────────────────
    printer_name = fields.Char(string='Printer', readonly=True)
    print_pages = fields.Integer(string='Pages', readonly=True)
    print_document = fields.Char(string='Document', readonly=True)

    # ── GENERAL ───────────────────────────────────────────────────────────────
    description = fields.Char(
        string='Description',
        readonly=True,
        compute='_compute_description',
        store=True,
    )
    risk_flag = fields.Boolean(
        string='Risk Flagged',
        readonly=True,
        default=False,
        help='Automatically flagged as potentially risky',
    )
    risk_reason = fields.Char(
        string='Risk Reason',
        readonly=True,
    )
    raw_data = fields.Text(
        string='Raw Data',
        readonly=True,
        groups='cyber_shield.group_cyber_admin',
    )

    # ── IMMUTABILITY ──────────────────────────────────────────────────────────
    def write(self, vals):
        raise AccessError(_('Activity records are immutable.'))

    def unlink(self):
        raise AccessError(_('Activity records cannot be deleted.'))

    # ── COMPUTE ───────────────────────────────────────────────────────────────
    @api.depends('file_path')
    def _compute_file_name(self):
        for rec in self:
            if rec.file_path:
                import os
                rec.file_name = os.path.basename(rec.file_path)
                _, ext = os.path.splitext(rec.file_path)
                rec.file_extension = ext.lower().lstrip('.')
            else:
                rec.file_name = False
                rec.file_extension = False

    @api.depends('url')
    def _compute_domain(self):
        for rec in self:
            if rec.url:
                try:
                    from urllib.parse import urlparse
                    rec.domain = urlparse(rec.url).netloc
                except Exception:
                    rec.domain = False
            else:
                rec.domain = False

    @api.depends('category', 'action', 'app_name', 'file_name', 'url', 'os_user')
    def _compute_description(self):
        action_labels = {
            'login': 'logged in', 'logout': 'logged out',
            'login_failed': 'failed login attempt',
            'app_start': 'started', 'app_stop': 'closed',
            'app_focus': 'focused on',
            'file_open': 'opened', 'file_create': 'created',
            'file_modify': 'modified', 'file_delete': 'deleted',
            'file_copy': 'copied', 'file_move': 'moved',
            'url_visit': 'visited', 'net_connect': 'connected to',
            'usb_connect': 'connected USB', 'usb_disconnect': 'disconnected USB',
            'usb_file_copy': 'copied file to USB',
            'boot': 'system booted', 'shutdown': 'system shutdown',
            'print_job': 'printed',
            'software_install': 'installed',
            'software_uninstall': 'uninstalled',
        }
        for rec in self:
            user = rec.os_user or 'Unknown user'
            action = action_labels.get(rec.action, rec.action or '')
            if rec.category == 'auth':
                rec.description = f"{user} {action}"
            elif rec.category == 'process':
                rec.description = f"{user} {action} {rec.app_name or ''}"
            elif rec.category == 'file':
                rec.description = f"{user} {action} {rec.file_name or rec.file_path or ''}"
            elif rec.category == 'network':
                rec.description = f"{user} {action} {rec.domain or rec.url or rec.remote_ip or ''}"
            elif rec.category == 'usb':
                rec.description = f"{user} {action} {rec.usb_device_name or ''}"
            elif rec.category == 'system':
                rec.description = f"{action} {rec.software_name or ''}"
            elif rec.category == 'print':
                rec.description = f"{user} printed {rec.print_document or ''} ({rec.print_pages or 0} pages) on {rec.printer_name or ''}"
            else:
                rec.description = f"{user} {action}"

    # ── RISK DETECTION ────────────────────────────────────────────────────────
    @api.model_create_multi
    def create(self, vals_list):
        """Create activity records and auto-flag risky ones."""
        for vals in vals_list:
            self._evaluate_risk(vals)
        records = super().create(vals_list)
        # Auto-create alert for high-risk activities
        for rec in records:
            if rec.risk_flag:
                self._auto_alert(rec)
        return records

    def _evaluate_risk(self, vals):
        """Evaluate if an activity is risky and flag it."""
        risky_extensions = {'exe', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'msi', 'dll'}
        risky_apps = {'mimikatz', 'procdump', 'netcat', 'nmap', 'wireshark', 'metasploit'}
        risky_domains = {'pastebin.com', 'transfer.sh', 'mega.nz', 'anonfiles.com'}
        risky_ports = {4444, 1337, 31337, 6667, 6697}

        reason = []

        # File risk
        ext = vals.get('file_extension', '') or ''
        if ext in risky_extensions and vals.get('action') in ('file_create', 'file_modify'):
            reason.append(f'Executable file created/modified: .{ext}')

        # App risk
        app = (vals.get('app_name') or '').lower()
        for risky in risky_apps:
            if risky in app:
                reason.append(f'Risky application: {app}')

        # USB file copy risk
        if vals.get('action') == 'usb_file_copy':
            reason.append('File copied to USB drive')

        # Network risk
        domain = (vals.get('domain') or '').lower()
        if domain in risky_domains:
            reason.append(f'Access to risky domain: {domain}')

        port = vals.get('remote_port', 0) or 0
        if port in risky_ports:
            reason.append(f'Connection to suspicious port: {port}')

        # Mass file deletion
        if vals.get('action') == 'file_delete':
            # Count recent deletions from same device
            pass  # Simplified for now

        if reason:
            vals['risk_flag'] = True
            vals['risk_reason'] = ' | '.join(reason)

    def _auto_alert(self, record):
        """Create a CyberShield alert for risky activities."""
        try:
            self.env['cyber.alert'].sudo().create({
                'name': f'[ACTIVITY] {record.description}',
                'device_id': record.device_id.id,
                'severity': 'high',
                'alert_type': 'anomaly',
                'description': f'Risky activity detected:\n{record.risk_reason}\n\nDetails: {record.description}\nUser: {record.os_user}\nTime: {record.timestamp}',
            })
        except Exception as e:
            _logger.error('CyberShield Activity: Error creating alert: %s', e)
