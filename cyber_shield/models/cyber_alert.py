# -*- coding: utf-8 -*-
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
from datetime import timedelta


class CyberAlert(models.Model):
    """
    CyberShield — Security Alert
    Risk-classified security alerts with full lifecycle management.
    Alerts are automatically created from high/critical log events
    and can also be created manually by analysts.
    """
    _name = 'cyber.alert'
    _description = 'CyberShield — Security Alert'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'severity_weight desc, create_date desc'

    # ── IDENTIFICATION ────────────────────────────────────────────────────────
    name = fields.Char(
        string='Alert Title',
        required=True,
        tracking=True,
    )
    reference = fields.Char(
        string='Reference',
        readonly=True,
        copy=False,
        default='New',
    )

    # ── CLASSIFICATION ────────────────────────────────────────────────────────
    severity = fields.Selection(
        selection=[
            ('critical', '🔴 Critical'),
            ('high', '🟠 High'),
            ('medium', '🟡 Medium'),
            ('low', '🟢 Low'),
            ('info', '🔵 Info'),
        ],
        string='Severity',
        required=True,
        default='medium',
        tracking=True,
        index=True,
    )
    severity_weight = fields.Integer(
        string='Severity Weight',
        compute='_compute_severity_weight',
        store=True,
    )
    alert_type = fields.Selection(
        selection=[
            ('intrusion', 'Intrusion Attempt'),
            ('malware', 'Malware Detection'),
            ('brute_force', 'Brute Force Attack'),
            ('data_exfiltration', 'Data Exfiltration'),
            ('privilege_escalation', 'Privilege Escalation'),
            ('lateral_movement', 'Lateral Movement'),
            ('anomaly', 'Anomalous Behavior'),
            ('policy_violation', 'Policy Violation'),
            ('vulnerability_exploit', 'Vulnerability Exploit'),
            ('dos', 'Denial of Service'),
            ('social_engineering', 'Social Engineering'),
            ('insider_threat', 'Insider Threat'),
            ('other', 'Other'),
        ],
        string='Alert Type',
        tracking=True,
    )

    # ── SOURCE ────────────────────────────────────────────────────────────────
    device_id = fields.Many2one(
        comodel_name='cyber.device',
        string='Source Device',
        required=True,
        ondelete='restrict',
        tracking=True,
        index=True,
    )
    log_id = fields.Many2one(
        comodel_name='cyber.log',
        string='Source Log',
        readonly=True,
        help='Log entry that triggered this alert',
    )
    source_ip = fields.Char(string='Source IP', tracking=True)
    destination_ip = fields.Char(string='Destination IP')
    destination_port = fields.Integer(string='Destination Port')

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
        tracking=True,
    )
    mitre_technique = fields.Char(
        string='MITRE Technique ID',
        help='e.g. T1078, T1059.001',
        tracking=True,
    )

    # ── LIFECYCLE ─────────────────────────────────────────────────────────────
    state = fields.Selection(
        selection=[
            ('new', 'New'),
            ('acknowledged', 'Acknowledged'),
            ('investigating', 'Investigating'),
            ('contained', 'Contained'),
            ('resolved', 'Resolved'),
            ('false_positive', 'False Positive'),
        ],
        string='State',
        default='new',
        tracking=True,
        index=True,
    )
    assigned_to_id = fields.Many2one(
        comodel_name='res.users',
        string='Assigned To',
        tracking=True,
    )
    acknowledged_by_id = fields.Many2one(
        comodel_name='res.users',
        string='Acknowledged By',
        readonly=True,
    )
    acknowledged_date = fields.Datetime(
        string='Acknowledged Date',
        readonly=True,
    )
    resolved_by_id = fields.Many2one(
        comodel_name='res.users',
        string='Resolved By',
        readonly=True,
    )
    resolved_date = fields.Datetime(
        string='Resolved Date',
        readonly=True,
    )
    resolution_notes = fields.Text(string='Resolution Notes')

    # ── SLA ───────────────────────────────────────────────────────────────────
    sla_deadline = fields.Datetime(
        string='SLA Deadline',
        compute='_compute_sla_deadline',
        store=True,
        help='Maximum time to resolve based on severity',
    )
    sla_breached = fields.Boolean(
        string='SLA Breached',
        compute='_compute_sla_breached',
        store=True,
    )

    # ── DETAILS ───────────────────────────────────────────────────────────────
    description = fields.Text(string='Description', required=True)
    remediation = fields.Text(
        string='Recommended Remediation',
        help='Recommended steps to resolve this alert',
    )

    # ── INCIDENT REFERENCE ────────────────────────────────────────────────────
    incident_id = fields.Many2one(
        comodel_name='cyber.incident',
        string='Related Incident',
        tracking=True,
    )

    # ── COMPUTE ───────────────────────────────────────────────────────────────
    @api.depends('severity')
    def _compute_severity_weight(self):
        weights = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25, 'info': 0}
        for rec in self:
            rec.severity_weight = weights.get(rec.severity, 0)

    @api.depends('create_date', 'severity')
    def _compute_sla_deadline(self):
        """SLA: CRITICAL=1h, HIGH=4h, MEDIUM=24h, LOW=72h"""
        sla_hours = {'critical': 1, 'high': 4, 'medium': 24, 'low': 72, 'info': 168}
        for rec in self:
            if rec.create_date and rec.severity:
                hours = sla_hours.get(rec.severity, 24)
                rec.sla_deadline = rec.create_date + timedelta(hours=hours)
            else:
                rec.sla_deadline = False

    @api.depends('sla_deadline', 'state')
    def _compute_sla_breached(self):
        now = fields.Datetime.now()
        for rec in self:
            rec.sla_breached = (
                rec.sla_deadline and
                now > rec.sla_deadline and
                rec.state not in ('resolved', 'false_positive')
            )

    # ── LIFECYCLE METHODS ─────────────────────────────────────────────────────
    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('reference', 'New') == 'New':
                vals['reference'] = self.env['ir.sequence'].next_by_code('cyber.alert')
        records = super().create(vals_list)
        for rec in records:
            if rec.severity == 'critical':
                rec._auto_create_incident()
        return records

    def action_acknowledge(self):
        self.ensure_one()
        self.write({
            'state': 'acknowledged',
            'acknowledged_by_id': self.env.user.id,
            'acknowledged_date': fields.Datetime.now(),
        })
        self.message_post(body=_('Alert acknowledged by %s') % self.env.user.name)

    def action_investigate(self):
        self.write({'state': 'investigating'})
        self.message_post(body=_('Investigation started by %s') % self.env.user.name)

    def action_contain(self):
        self.write({'state': 'contained'})
        self.message_post(body=_('Alert contained by %s') % self.env.user.name)

    def action_resolve(self):
        if not self.resolution_notes:
            raise ValidationError(_('Please provide resolution notes before resolving the alert.'))
        self.write({
            'state': 'resolved',
            'resolved_by_id': self.env.user.id,
            'resolved_date': fields.Datetime.now(),
        })
        self.message_post(body=_('Alert resolved by %s') % self.env.user.name)

    def action_false_positive(self):
        self.write({'state': 'false_positive'})
        self.message_post(body=_('Marked as false positive by %s') % self.env.user.name)

    def _auto_create_incident(self):
        """Auto-create incident for CRITICAL alerts."""
        incident = self.env['cyber.incident'].sudo().create({
            'name': f'[AUTO] {self.name}',
            'device_id': self.device_id.id,
            'severity': 'critical',
            'description': f'Auto-generated from CRITICAL alert: {self.reference}\n\n{self.description}',
            'source': 'automatic',
        })
        self.incident_id = incident.id
        self.message_post(
            body=_('Incident %s automatically created from this CRITICAL alert.') % incident.reference
        )
