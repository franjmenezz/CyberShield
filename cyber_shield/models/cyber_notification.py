# -*- coding: utf-8 -*-
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.

"""
CyberShield — Notification Center Models
==========================================
Self-contained notification system with:
  - Notification channels (Email, Webhook, ODOO internal)
  - Message templates per event type
  - Escalation rules with SLA-based triggering
  - Full notification history with delivery status
  - No dependency on external services (webhooks are optional)
"""

import hashlib
import json
import logging
import urllib.request
import urllib.error
from datetime import timedelta

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION CHANNEL
# ══════════════════════════════════════════════════════════════════════════════
class CyberNotificationChannel(models.Model):
    """
    CyberShield — Notification Channel
    Defines WHERE notifications are sent.
    Supported: ODOO internal, Email, Webhook (Telegram, Slack, Teams, custom...)
    """
    _name = 'cyber.notification.channel'
    _description = 'CyberShield — Notification Channel'
    _inherit = ['mail.thread']
    _order = 'name'

    name = fields.Char(string='Channel Name', required=True, tracking=True)
    channel_type = fields.Selection(
        selection=[
            ('odoo', 'ODOO Internal Notification'),
            ('email', 'Email'),
            ('webhook', 'Webhook (Telegram / Slack / Teams / Custom)'),
        ],
        string='Channel Type',
        required=True,
        default='odoo',
        tracking=True,
    )
    active = fields.Boolean(default=True, tracking=True)
    description = fields.Char(string='Description')

    # ── ODOO INTERNAL ─────────────────────────────────────────────────────────
    odoo_user_ids = fields.Many2many(
        comodel_name='res.users',
        relation='cyber_channel_users_rel',
        string='Notify Users',
        help='ODOO users who will receive internal notifications',
    )

    # ── EMAIL ─────────────────────────────────────────────────────────────────
    email_to = fields.Char(
        string='Email Addresses',
        help='Comma-separated list of email addresses',
    )
    email_cc = fields.Char(string='CC Addresses')

    # ── WEBHOOK ───────────────────────────────────────────────────────────────
    webhook_url = fields.Char(
        string='Webhook URL',
        groups='cyber_shield.group_cyber_admin',
        help='URL to POST the notification payload to.\n'
             'Examples:\n'
             '  Telegram: https://api.telegram.org/bot{TOKEN}/sendMessage\n'
             '  Slack: https://hooks.slack.com/services/...\n'
             '  Teams: https://outlook.office.com/webhook/...\n'
             '  Custom: https://your-server.com/webhook',
    )
    webhook_method = fields.Selection(
        selection=[('POST', 'POST'), ('GET', 'GET')],
        string='HTTP Method',
        default='POST',
    )
    webhook_headers = fields.Text(
        string='Custom Headers (JSON)',
        help='Optional JSON object with custom HTTP headers\n'
             'Example: {"Authorization": "Bearer token123"}',
        groups='cyber_shield.group_cyber_admin',
    )
    webhook_payload_template = fields.Text(
        string='Payload Template (JSON)',
        help='JSON template for the webhook body.\n'
             'Available variables: {title}, {message}, {severity}, {device}, {reference}\n\n'
             'Telegram example:\n'
             '{"chat_id": "-100123456789", "text": "{message}", "parse_mode": "HTML"}',
    )
    webhook_timeout = fields.Integer(
        string='Timeout (seconds)',
        default=10,
    )

    # ── TEST ──────────────────────────────────────────────────────────────────
    notification_count = fields.Integer(
        string='Notifications Sent',
        compute='_compute_notification_count',
    )

    @api.depends()
    def _compute_notification_count(self):
        for rec in self:
            rec.notification_count = self.env['cyber.notification'].search_count(
                [('channel_id', '=', rec.id)]
            )

    @api.constrains('webhook_headers')
    def _check_webhook_headers(self):
        for rec in self:
            if rec.webhook_headers:
                try:
                    json.loads(rec.webhook_headers)
                except (json.JSONDecodeError, ValueError):
                    raise ValidationError(_('Webhook headers must be valid JSON.'))

    @api.constrains('webhook_payload_template')
    def _check_webhook_payload(self):
        for rec in self:
            if rec.webhook_payload_template:
                try:
                    json.loads(rec.webhook_payload_template.replace(
                        '{title}', 'test').replace('{message}', 'test')
                        .replace('{severity}', 'test').replace('{device}', 'test')
                        .replace('{reference}', 'test'))
                except (json.JSONDecodeError, ValueError):
                    raise ValidationError(_('Webhook payload template must be valid JSON.'))

    def action_test_channel(self):
        """Send a test notification to verify the channel works."""
        self.ensure_one()
        test_notification = self.env['cyber.notification'].create({
            'title': '🛡️ CyberShield — Channel Test',
            'message': f'This is a test notification from channel: {self.name}\nIf you receive this, the channel is working correctly.',
            'severity': 'info',
            'channel_id': self.id,
            'notification_type': 'test',
        })
        test_notification._send()
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Test Sent'),
                'message': _('Test notification sent to channel "%s". Check the notification history.') % self.name,
                'type': 'success',
                'sticky': False,
            }
        }

    def action_view_notifications(self):
        return {
            'name': _('Notifications — %s') % self.name,
            'type': 'ir.actions.act_window',
            'res_model': 'cyber.notification',
            'view_mode': 'list,form',
            'domain': [('channel_id', '=', self.id)],
        }


# ══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION TEMPLATE
# ══════════════════════════════════════════════════════════════════════════════
class CyberNotificationTemplate(models.Model):
    """
    CyberShield — Notification Template
    Defines HOW notifications look for each severity/event type.
    """
    _name = 'cyber.notification.template'
    _description = 'CyberShield — Notification Template'
    _order = 'severity, name'

    name = fields.Char(string='Template Name', required=True)
    severity = fields.Selection(
        selection=[
            ('critical', '🔴 Critical'),
            ('high', '🟠 High'),
            ('medium', '🟡 Medium'),
            ('low', '🟢 Low'),
            ('info', '🔵 Info'),
        ],
        string='For Severity',
        required=True,
    )
    event_type = fields.Selection(
        selection=[
            ('any', 'Any Event'),
            ('login_failed', 'Failed Login'),
            ('privilege_escalation', 'Privilege Escalation'),
            ('malware_detected', 'Malware Detected'),
            ('remote_access', 'Remote Access'),
            ('usb_connected', 'USB Device'),
            ('network_connection', 'Suspicious Network'),
            ('other', 'Other'),
        ],
        string='For Event Type',
        default='any',
    )
    subject_template = fields.Char(
        string='Subject / Title Template',
        required=True,
        default='[{severity}] CyberShield Alert: {name}',
        help='Available variables: {severity}, {name}, {device}, {reference}, {timestamp}',
    )
    body_template = fields.Text(
        string='Body Template',
        required=True,
        help='Available variables: {severity}, {name}, {device}, {reference}, {timestamp}, {description}, {mitre_tactic}, {mitre_technique}, {source_ip}, {assigned_to}',
    )
    active = fields.Boolean(default=True)

    @api.model
    def _get_default_template(self, severity):
        """Get or create the default template for a given severity."""
        template = self.search([
            ('severity', '=', severity),
            ('event_type', '=', 'any'),
            ('active', '=', True),
        ], limit=1)
        return template

    def render(self, alert):
        """Render template with alert data."""
        self.ensure_one()
        vals = {
            'severity': (alert.severity or '').upper(),
            'name': alert.name or '',
            'device': alert.device_id.display_name if alert.device_id else 'Unknown',
            'reference': alert.reference or '',
            'timestamp': fields.Datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            'description': alert.description or '',
            'mitre_tactic': alert.mitre_tactic or 'N/A',
            'mitre_technique': alert.mitre_technique or 'N/A',
            'source_ip': alert.source_ip or 'N/A',
            'assigned_to': alert.assigned_to_id.name if alert.assigned_to_id else 'Unassigned',
        }
        subject = self.subject_template
        body = self.body_template
        for key, value in vals.items():
            subject = subject.replace('{' + key + '}', str(value))
            body = body.replace('{' + key + '}', str(value))
        return subject, body


# ══════════════════════════════════════════════════════════════════════════════
# ESCALATION RULE
# ══════════════════════════════════════════════════════════════════════════════
class CyberEscalationRule(models.Model):
    """
    CyberShield — Escalation Rule
    Defines WHEN and to WHOM notifications are sent.
    Rules are evaluated automatically when alerts are created or updated.
    """
    _name = 'cyber.escalation.rule'
    _description = 'CyberShield — Escalation Rule'
    _order = 'sequence, name'

    name = fields.Char(string='Rule Name', required=True)
    sequence = fields.Integer(string='Priority', default=10)
    active = fields.Boolean(default=True)
    description = fields.Char(string='Description')

    # ── TRIGGER CONDITIONS ────────────────────────────────────────────────────
    trigger_severity = fields.Selection(
        selection=[
            ('critical', '🔴 Critical only'),
            ('high', '🟠 High and above'),
            ('medium', '🟡 Medium and above'),
            ('low', '🟢 All alerts'),
        ],
        string='Trigger on Severity',
        required=True,
        default='critical',
    )
    trigger_event = fields.Selection(
        selection=[
            ('alert_created', 'Alert Created'),
            ('alert_unacknowledged', 'Alert not acknowledged within SLA'),
            ('incident_created', 'Incident Created'),
            ('sla_breached', 'SLA Breached'),
            ('device_offline', 'Device went offline'),
        ],
        string='Trigger on Event',
        required=True,
        default='alert_created',
    )
    delay_minutes = fields.Integer(
        string='Delay (minutes)',
        default=0,
        help='Wait this many minutes before sending. 0 = immediate.',
    )
    repeat_after_minutes = fields.Integer(
        string='Repeat every (minutes)',
        default=0,
        help='Repeat notification if not acknowledged. 0 = no repeat.',
    )
    max_repeats = fields.Integer(
        string='Max Repeats',
        default=3,
        help='Maximum number of repeat notifications. 0 = unlimited.',
    )

    # ── CHANNELS & TEMPLATE ───────────────────────────────────────────────────
    channel_ids = fields.Many2many(
        comodel_name='cyber.notification.channel',
        relation='cyber_rule_channel_rel',
        string='Notify via Channels',
        required=True,
    )
    template_id = fields.Many2one(
        comodel_name='cyber.notification.template',
        string='Message Template',
        help='Leave empty to use the default template for the alert severity',
    )

    # ── FILTER CONDITIONS ─────────────────────────────────────────────────────
    device_type_filter = fields.Selection(
        selection=[
            ('any', 'Any device'),
            ('workstation', 'Workstations only'),
            ('server', 'Servers only'),
        ],
        string='Apply to Device Type',
        default='any',
    )
    department_filter = fields.Char(
        string='Department Filter',
        help='Only trigger for devices in this department (leave empty for all)',
    )

    # ── STATS ─────────────────────────────────────────────────────────────────
    trigger_count = fields.Integer(
        string='Times Triggered',
        readonly=True,
        default=0,
    )
    last_triggered = fields.Datetime(
        string='Last Triggered',
        readonly=True,
    )

    def _severity_matches(self, alert_severity):
        """Check if alert severity matches rule trigger level."""
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        trigger_map = {
            'critical': 4, 'high': 3, 'medium': 2, 'low': 1
        }
        alert_level = severity_order.get(alert_severity, 0)
        required_level = trigger_map.get(self.trigger_severity, 4)
        return alert_level >= required_level

    def evaluate_and_notify(self, alert):
        """Evaluate this rule against an alert and send notifications if applicable."""
        self.ensure_one()

        if not self._severity_matches(alert.severity):
            return False

        if self.device_type_filter != 'any' and alert.device_id:
            if alert.device_id.device_type not in (self.device_type_filter,):
                return False

        # Get template
        template = self.template_id
        if not template:
            template = self.env['cyber.notification.template']._get_default_template(
                alert.severity
            )

        # Send to all channels
        for channel in self.channel_ids:
            self.env['cyber.notification'].create({
                'alert_id': alert.id,
                'channel_id': channel.id,
                'rule_id': self.id,
                'template_id': template.id if template else False,
                'severity': alert.severity,
                'notification_type': 'alert',
                'title': f'[{alert.severity.upper()}] {alert.name}',
                'message': self._build_message(alert),
            })._send()

        # Update stats
        self.sudo().write({
            'trigger_count': self.trigger_count + 1,
            'last_triggered': fields.Datetime.now(),
        })
        return True

    def _build_message(self, alert):
        """Build the notification message body."""
        severity_emoji = {
            'critical': '🔴', 'high': '🟠', 'medium': '🟡',
            'low': '🟢', 'info': '🔵'
        }
        emoji = severity_emoji.get(alert.severity, '⚠️')
        lines = [
            f"{emoji} <b>CyberShield Security Alert</b>",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"<b>Severity:</b> {alert.severity.upper()}",
            f"<b>Alert:</b> {alert.name}",
            f"<b>Reference:</b> {alert.reference}",
            f"<b>Device:</b> {alert.device_id.display_name if alert.device_id else 'Unknown'}",
            f"<b>Time:</b> {fields.Datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        ]
        if alert.description:
            lines.append(f"<b>Description:</b> {alert.description[:300]}")
        if alert.mitre_tactic:
            lines.append(f"<b>MITRE Tactic:</b> {alert.mitre_tactic}")
        if alert.mitre_technique:
            lines.append(f"<b>MITRE Technique:</b> {alert.mitre_technique}")
        if alert.source_ip:
            lines.append(f"<b>Source IP:</b> {alert.source_ip}")
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"<i>CyberShield v1.0.0 — Powered by Francisco José Jiménez Pozo</i>")
        return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION (History)
# ══════════════════════════════════════════════════════════════════════════════
class CyberNotification(models.Model):
    """
    CyberShield — Notification
    Complete history of every notification sent by CyberShield.
    Each record tracks what was sent, when, to which channel, and delivery status.
    """
    _name = 'cyber.notification'
    _description = 'CyberShield — Notification History'
    _order = 'create_date desc'
    _log_access = False

    # ── CONTENT ───────────────────────────────────────────────────────────────
    title = fields.Char(string='Title', required=True, readonly=True)
    message = fields.Text(string='Message', required=True, readonly=True)
    severity = fields.Selection(
        selection=[
            ('critical', '🔴 Critical'),
            ('high', '🟠 High'),
            ('medium', '🟡 Medium'),
            ('low', '🟢 Low'),
            ('info', '🔵 Info'),
        ],
        string='Severity',
        readonly=True,
    )
    notification_type = fields.Selection(
        selection=[
            ('alert', 'Alert Notification'),
            ('incident', 'Incident Notification'),
            ('escalation', 'Escalation'),
            ('test', 'Test'),
            ('digest', 'Daily Digest'),
        ],
        string='Type',
        default='alert',
        readonly=True,
    )

    # ── DELIVERY ──────────────────────────────────────────────────────────────
    channel_id = fields.Many2one(
        comodel_name='cyber.notification.channel',
        string='Channel',
        readonly=True,
        ondelete='set null',
    )
    state = fields.Selection(
        selection=[
            ('pending', 'Pending'),
            ('sent', 'Sent ✅'),
            ('failed', 'Failed ❌'),
            ('skipped', 'Skipped'),
        ],
        string='Delivery Status',
        default='pending',
        readonly=True,
        index=True,
    )
    sent_at = fields.Datetime(string='Sent At', readonly=True)
    error_message = fields.Text(string='Error Message', readonly=True)
    retry_count = fields.Integer(string='Retry Count', default=0, readonly=True)

    # ── REFERENCES ────────────────────────────────────────────────────────────
    alert_id = fields.Many2one(
        comodel_name='cyber.alert',
        string='Alert',
        readonly=True,
        ondelete='set null',
    )
    incident_id = fields.Many2one(
        comodel_name='cyber.incident',
        string='Incident',
        readonly=True,
        ondelete='set null',
    )
    rule_id = fields.Many2one(
        comodel_name='cyber.escalation.rule',
        string='Triggered by Rule',
        readonly=True,
        ondelete='set null',
    )
    template_id = fields.Many2one(
        comodel_name='cyber.notification.template',
        string='Template Used',
        readonly=True,
        ondelete='set null',
    )

    # ── SEND METHODS ──────────────────────────────────────────────────────────
    def _send(self):
        """Dispatch notification to the appropriate channel."""
        self.ensure_one()
        if not self.channel_id:
            self._mark_skipped('No channel assigned')
            return

        channel = self.channel_id
        try:
            if channel.channel_type == 'odoo':
                self._send_odoo_internal()
            elif channel.channel_type == 'email':
                self._send_email()
            elif channel.channel_type == 'webhook':
                self._send_webhook()
            else:
                self._mark_skipped(f'Unknown channel type: {channel.channel_type}')
                return

            self.sudo().write({
                'state': 'sent',
                'sent_at': fields.Datetime.now(),
            })
            _logger.info('CyberShield notification sent via %s: %s', channel.channel_type, self.title)

        except Exception as e:
            error = str(e)[:500]
            _logger.error('CyberShield notification failed via %s: %s', channel.channel_type, error)
            self.sudo().write({
                'state': 'failed',
                'error_message': error,
                'retry_count': self.retry_count + 1,
            })

    def _send_odoo_internal(self):
        """Send ODOO internal notification to configured users."""
        channel = self.channel_id
        if not channel.odoo_user_ids:
            self._mark_skipped('No users configured for ODOO internal channel')
            return

        for user in channel.odoo_user_ids:
            self.env['mail.message'].sudo().create({
                'message_type': 'notification',
                'subtype_id': self.env.ref('mail.mt_note').id,
                'body': f'<b>{self.title}</b><br/>{self.message.replace(chr(10), "<br/>")}',
                'partner_ids': [(4, user.partner_id.id)],
                'author_id': self.env.ref('base.user_root').partner_id.id,
            })

    def _send_email(self):
        """Send email notification via ODOO mail system."""
        channel = self.channel_id
        if not channel.email_to:
            self._mark_skipped('No email addresses configured')
            return

        self.env['mail.mail'].sudo().create({
            'subject': self.title,
            'body_html': f'<div style="font-family:Arial,sans-serif;">{self.message.replace(chr(10), "<br/>")}</div>',
            'email_to': channel.email_to,
            'email_cc': channel.email_cc or False,
            'auto_delete': True,
        }).send()

    def _send_webhook(self):
        """
        Send notification via HTTP webhook.
        Supports Telegram, Slack, Teams, or any custom endpoint.
        The payload is built from the channel's payload template.
        """
        channel = self.channel_id
        if not channel.webhook_url:
            self._mark_skipped('No webhook URL configured')
            return

        # Build payload from template or use default
        if channel.webhook_payload_template:
            payload_str = channel.webhook_payload_template
            for key, val in {
                '{title}': self.title,
                '{message}': self.message,
                '{severity}': self.severity or '',
                '{device}': self.alert_id.device_id.display_name if self.alert_id and self.alert_id.device_id else 'Unknown',
                '{reference}': self.alert_id.reference if self.alert_id else '',
            }.items():
                payload_str = payload_str.replace(key, str(val).replace('"', '\\"'))
            payload = payload_str.encode('utf-8')
        else:
            # Default JSON payload
            default_payload = {
                'source': 'CyberShield',
                'title': self.title,
                'message': self.message,
                'severity': self.severity,
                'timestamp': str(fields.Datetime.now()),
                'alert_reference': self.alert_id.reference if self.alert_id else None,
            }
            payload = json.dumps(default_payload).encode('utf-8')

        # Build headers
        headers = {'Content-Type': 'application/json'}
        if channel.webhook_headers:
            try:
                custom_headers = json.loads(channel.webhook_headers)
                headers.update(custom_headers)
            except Exception:
                pass

        req = urllib.request.Request(
            url=channel.webhook_url,
            data=payload,
            headers=headers,
            method=channel.webhook_method or 'POST',
        )

        timeout = channel.webhook_timeout or 10
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.status
            if status not in (200, 201, 202, 204):
                raise Exception(f'Webhook returned HTTP {status}')

    def _mark_skipped(self, reason):
        self.sudo().write({'state': 'skipped', 'error_message': reason})

    def action_retry(self):
        """Retry a failed notification."""
        self.ensure_one()
        if self.state != 'failed':
            raise ValidationError(_('Only failed notifications can be retried.'))
        if self.retry_count >= 5:
            raise ValidationError(_('Maximum retry count (5) reached.'))
        self.sudo().write({'state': 'pending', 'error_message': False})
        self._send()
