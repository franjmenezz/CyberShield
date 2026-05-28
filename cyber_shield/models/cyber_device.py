# -*- coding: utf-8 -*-
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.
# Unauthorized copying or distribution is strictly prohibited.

import hashlib
import uuid
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class CyberDevice(models.Model):
    """
    CyberShield — Device Model
    Represents a monitored endpoint (PC or server) in the organization.
    Each device is uniquely identified and has its own agent token for
    secure API communication using Zero Trust principles.
    """
    _name = 'cyber.device'
    _description = 'CyberShield — Monitored Device'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'device_type, name'
    _rec_name = 'display_name'

    # ── IDENTIFICATION ────────────────────────────────────────────────────────
    name = fields.Char(
        string='Device Name',
        required=True,
        tracking=True,
        help='Unique device identifier (e.g. Diseño EQ1, Contabilidad EQ1)',
    )
    display_name = fields.Char(
        string='Display Name',
        compute='_compute_display_name',
        store=True,
    )
    device_uid = fields.Char(
        string='Device UID',
        readonly=True,
        copy=False,
        index=True,
        help='Unique immutable identifier generated on creation (UUID4)',
    )
    agent_token = fields.Char(
        string='Agent Token',
        readonly=True,
        copy=False,
        groups='cyber_shield.group_cyber_admin',
        help='Secret token used by the Wazuh agent to authenticate to the API',
    )

    # ── CLASSIFICATION ────────────────────────────────────────────────────────
    device_type = fields.Selection(
        selection=[
            ('workstation', 'Workstation (PC)'),
            ('server', 'Server'),
            ('laptop', 'Laptop'),
            ('virtual', 'Virtual Machine'),
            ('network', 'Network Device'),
            ('other', 'Other'),
        ],
        string='Device Type',
        required=True,
        default='workstation',
        tracking=True,
    )
    department = fields.Selection(
        selection=[
            ('design', 'Design'),
            ('accounting', 'Accounting / Finance'),
            ('sales', 'Sales'),
            ('management', 'Management'),
            ('it', 'IT / Systems'),
            ('operations', 'Operations / Field'),
            ('hr', 'Human Resources'),
            ('other', 'Other'),
        ],
        string='Department',
        required=True,
        tracking=True,
    )
    location = fields.Char(
        string='Physical Location',
        help='Physical location of the device (e.g. Office floor 1, Server room)',
    )
    criticality = fields.Selection(
        selection=[
            ('critical', 'Critical'),
            ('high', 'High'),
            ('medium', 'Medium'),
            ('low', 'Low'),
        ],
        string='Asset Criticality',
        required=True,
        default='medium',
        tracking=True,
        help='Business criticality of this asset',
    )

    # ── TECHNICAL INFO ────────────────────────────────────────────────────────
    os_type = fields.Selection(
        selection=[
            ('windows_11', 'Windows 11'),
            ('windows_10', 'Windows 10'),
            ('windows_server_2022', 'Windows Server 2022'),
            ('windows_server_2019', 'Windows Server 2019'),
            ('ubuntu_22', 'Ubuntu 22.04 LTS'),
            ('ubuntu_20', 'Ubuntu 20.04 LTS'),
            ('debian_12', 'Debian 12'),
            ('rhel_9', 'RHEL 9'),
            ('other_linux', 'Other Linux'),
            ('other', 'Other'),
        ],
        string='Operating System',
        tracking=True,
    )
    os_version = fields.Char(string='OS Version / Build')
    ip_address = fields.Char(
        string='IP Address',
        tracking=True,
        help='Primary IP address of the device',
    )
    mac_address = fields.Char(string='MAC Address')
    hostname = fields.Char(string='Hostname')
    serial_number = fields.Char(string='Serial Number')
    manufacturer = fields.Char(string='Manufacturer')
    model = fields.Char(string='Model')

    # ── AGENT STATUS ──────────────────────────────────────────────────────────
    status = fields.Selection(
        selection=[
            ('active', 'Active'),
            ('inactive', 'Inactive'),
            ('warning', 'Warning'),
            ('critical', 'Critical'),
            ('offline', 'Offline'),
            ('unregistered', 'Unregistered'),
        ],
        string='Status',
        default='unregistered',
        tracking=True,
        readonly=True,
    )
    agent_status = fields.Selection(
        selection=[
            ('connected', 'Connected'),
            ('disconnected', 'Disconnected'),
            ('never_connected', 'Never Connected'),
        ],
        string='Agent Status',
        default='never_connected',
        readonly=True,
    )
    wazuh_agent_id = fields.Char(
        string='Wazuh Agent ID',
        readonly=True,
        help='Agent ID assigned by Wazuh Manager',
    )
    last_seen = fields.Datetime(
        string='Last Seen',
        readonly=True,
        help='Last time the agent sent data to the server',
    )
    agent_version = fields.Char(string='Agent Version', readonly=True)

    # ── ASSIGNMENT ────────────────────────────────────────────────────────────
    assigned_user_id = fields.Many2one(
        comodel_name='res.users',
        string='Assigned User',
        tracking=True,
        help='Primary user of this device',
    )
    responsible_id = fields.Many2one(
        comodel_name='res.users',
        string='IT Responsible',
        default=lambda self: self.env.user,
        tracking=True,
    )

    # ── RELATIONS ─────────────────────────────────────────────────────────────
    log_ids = fields.One2many(
        comodel_name='cyber.log',
        inverse_name='device_id',
        string='Activity Logs',
    )
    alert_ids = fields.One2many(
        comodel_name='cyber.alert',
        inverse_name='device_id',
        string='Alerts',
    )
    vulnerability_ids = fields.One2many(
        comodel_name='cyber.vulnerability',
        inverse_name='device_id',
        string='Vulnerabilities',
    )
    incident_ids = fields.One2many(
        comodel_name='cyber.incident',
        inverse_name='device_id',
        string='Incidents',
    )

    # ── COMPUTED COUNTS ───────────────────────────────────────────────────────
    log_count = fields.Integer(
        string='Logs',
        compute='_compute_counts',
    )
    alert_count = fields.Integer(
        string='Alerts',
        compute='_compute_counts',
    )
    critical_alert_count = fields.Integer(
        string='Critical Alerts',
        compute='_compute_counts',
    )
    vulnerability_count = fields.Integer(
        string='Vulnerabilities',
        compute='_compute_counts',
    )
    incident_count = fields.Integer(
        string='Incidents',
        compute='_compute_counts',
    )
    risk_score = fields.Integer(
        string='Risk Score',
        compute='_compute_risk_score',
        store=True,
        help='Calculated risk score 0-100 based on alerts and vulnerabilities',
    )

    # ── NOTES ─────────────────────────────────────────────────────────────────
    notes = fields.Html(string='Notes')
    active = fields.Boolean(default=True)

    # ── CONSTRAINTS ───────────────────────────────────────────────────────────
    _sql_constraints = [
        ('device_uid_unique', 'UNIQUE(device_uid)', 'Device UID must be unique.'),
        ('agent_token_unique', 'UNIQUE(agent_token)', 'Agent token must be unique.'),
    ]

    @api.constrains('ip_address')
    def _check_ip_address(self):
        """Validate IP address format."""
        import re
        ip_pattern = re.compile(
            r'^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F:]+)$'
        )
        for rec in self:
            if rec.ip_address and not ip_pattern.match(rec.ip_address):
                raise ValidationError(_('Invalid IP address format: %s') % rec.ip_address)

    # ── COMPUTE METHODS ───────────────────────────────────────────────────────
    @api.depends('name', 'department', 'device_type')
    def _compute_display_name(self):
        dept_map = {
            'design': 'Diseño',
            'accounting': 'Contabilidad',
            'sales': 'Ventas',
            'management': 'Dirección',
            'it': 'IT',
            'operations': 'Operaciones',
            'hr': 'RRHH',
            'other': 'Otro',
        }
        for rec in self:
            dept = dept_map.get(rec.department, '') if rec.department else ''
            rec.display_name = f"{dept} — {rec.name}" if dept else rec.name

    @api.depends('log_ids', 'alert_ids', 'vulnerability_ids', 'incident_ids')
    def _compute_counts(self):
        for rec in self:
            rec.log_count = len(rec.log_ids)
            rec.alert_count = len(rec.alert_ids)
            rec.critical_alert_count = len(
                rec.alert_ids.filtered(lambda a: a.severity == 'critical')
            )
            rec.vulnerability_count = len(rec.vulnerability_ids)
            rec.incident_count = len(rec.incident_ids)

    @api.depends('alert_ids.severity', 'vulnerability_ids.cvss_score', 'criticality')
    def _compute_risk_score(self):
        """
        Calculate device risk score (0-100) based on:
        - Active critical alerts: +30 each (max 60)
        - Active high alerts: +10 each (max 30)
        - CVSS vulnerabilities average
        - Asset criticality multiplier
        """
        criticality_mult = {'critical': 1.5, 'high': 1.25, 'medium': 1.0, 'low': 0.75}
        for rec in self:
            score = 0
            open_alerts = rec.alert_ids.filtered(lambda a: a.state not in ['resolved', 'false_positive'])
            score += min(len(open_alerts.filtered(lambda a: a.severity == 'critical')) * 30, 60)
            score += min(len(open_alerts.filtered(lambda a: a.severity == 'high')) * 10, 30)
            if rec.vulnerability_ids:
                avg_cvss = sum(rec.vulnerability_ids.mapped('cvss_score')) / len(rec.vulnerability_ids)
                score += avg_cvss * 2
            mult = criticality_mult.get(rec.criticality, 1.0)
            rec.risk_score = min(int(score * mult), 100)

    # ── LIFECYCLE ─────────────────────────────────────────────────────────────
    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if not vals.get('device_uid'):
                vals['device_uid'] = str(uuid.uuid4())
            if not vals.get('agent_token'):
                vals['agent_token'] = self._generate_agent_token(vals.get('device_uid', ''))
        return super().create(vals_list)

    def _generate_agent_token(self, device_uid):
        """Generate a secure agent token using SHA-256 + UUID4 salt."""
        salt = str(uuid.uuid4())
        raw = f"{device_uid}:{salt}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def action_regenerate_token(self):
        """Regenerate agent token — requires admin rights."""
        self.ensure_one()
        if not self.env.user.has_group('cyber_shield.group_cyber_admin'):
            raise ValidationError(_('Only CyberShield Administrators can regenerate agent tokens.'))
        self.agent_token = self._generate_agent_token(self.device_uid)
        self.message_post(body=_('Agent token regenerated by %s') % self.env.user.name)

    def action_view_logs(self):
        return {
            'name': _('Activity Logs — %s') % self.display_name,
            'type': 'ir.actions.act_window',
            'res_model': 'cyber.log',
            'view_mode': 'list,form',
            'domain': [('device_id', '=', self.id)],
            'context': {'default_device_id': self.id},
        }

    def action_view_alerts(self):
        return {
            'name': _('Alerts — %s') % self.display_name,
            'type': 'ir.actions.act_window',
            'res_model': 'cyber.alert',
            'view_mode': 'list,form',
            'domain': [('device_id', '=', self.id)],
            'context': {'default_device_id': self.id},
        }
