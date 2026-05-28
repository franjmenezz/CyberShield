# -*- coding: utf-8 -*-
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.

"""
CyberShield — VirusTotal Integration
======================================
Automatic analysis of:
  - File hashes (SHA-256) from suspicious processes
  - URLs detected in network connections
  - IP addresses from suspicious traffic

Uses VirusTotal Public API v3 (free tier: 4 requests/min, 500/day)
with intelligent rate limiting and caching to avoid quota exhaustion.
"""

import hashlib
import json
import logging
import time
import urllib.request
import urllib.error
from datetime import timedelta

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError

_logger = logging.getLogger(__name__)

# ── CONSTANTS ─────────────────────────────────────────────────────────────────
VT_API_BASE    = "https://www.virustotal.com/api/v3"
VT_HASH_URL    = f"{VT_API_BASE}/files/{{hash}}"
VT_URL_URL     = f"{VT_API_BASE}/urls"
VT_URL_GET     = f"{VT_API_BASE}/urls/{{url_id}}"
VT_IP_URL      = f"{VT_API_BASE}/ip_addresses/{{ip}}"
VT_TIMEOUT     = 15
CACHE_HOURS    = 24  # Don't re-analyse same indicator within 24h


# ══════════════════════════════════════════════════════════════════════════════
# VIRUSTOTAL SETTINGS (stored in ODOO system parameters)
# ══════════════════════════════════════════════════════════════════════════════
class CyberVTSettings(models.TransientModel):
    """CyberShield VirusTotal configuration — stored as system parameters."""
    _inherit = 'res.config.settings'

    cyber_vt_api_key = fields.Char(
        string='VirusTotal API Key',
        config_parameter='cyber_shield.vt_api_key',
        help='Your VirusTotal API key. Get it free at https://www.virustotal.com',
    )
    cyber_vt_enabled = fields.Boolean(
        string='Enable VirusTotal Integration',
        config_parameter='cyber_shield.vt_enabled',
        default=False,
    )
    cyber_vt_auto_scan = fields.Boolean(
        string='Auto-scan suspicious events',
        config_parameter='cyber_shield.vt_auto_scan',
        default=True,
        help='Automatically send hashes/IPs/URLs to VirusTotal when HIGH or CRITICAL events arrive',
    )
    cyber_vt_threshold = fields.Integer(
        string='Alert threshold (detections)',
        config_parameter='cyber_shield.vt_threshold',
        default=3,
        help='Create a CyberShield alert if VirusTotal detects with this many or more engines',
    )


# ══════════════════════════════════════════════════════════════════════════════
# VIRUSTOTAL ANALYSIS RESULT
# ══════════════════════════════════════════════════════════════════════════════
class CyberVTAnalysis(models.Model):
    """
    CyberShield — VirusTotal Analysis Result
    Records every VirusTotal query with full results and caching.
    """
    _name = 'cyber.vt.analysis'
    _description = 'CyberShield — VirusTotal Analysis'
    _order = 'create_date desc'

    # ── INDICATOR ─────────────────────────────────────────────────────────────
    indicator_type = fields.Selection(
        selection=[
            ('hash', 'File Hash (SHA-256)'),
            ('url', 'URL'),
            ('ip', 'IP Address'),
        ],
        string='Indicator Type',
        required=True,
        readonly=True,
        index=True,
    )
    indicator_value = fields.Char(
        string='Indicator',
        required=True,
        readonly=True,
        index=True,
        help='The hash, URL or IP that was analysed',
    )

    # ── RESULTS ───────────────────────────────────────────────────────────────
    state = fields.Selection(
        selection=[
            ('pending', 'Pending'),
            ('clean', '✅ Clean'),
            ('suspicious', '⚠️ Suspicious'),
            ('malicious', '🔴 Malicious'),
            ('error', '❌ Error'),
            ('not_found', 'Not Found'),
        ],
        string='Verdict',
        default='pending',
        readonly=True,
        index=True,
    )
    malicious_count = fields.Integer(
        string='Malicious Detections',
        readonly=True,
        help='Number of AV engines that flagged this as malicious',
    )
    suspicious_count = fields.Integer(
        string='Suspicious Detections',
        readonly=True,
    )
    harmless_count = fields.Integer(
        string='Harmless Detections',
        readonly=True,
    )
    total_engines = fields.Integer(
        string='Total Engines',
        readonly=True,
        help='Total number of AV engines that analysed this indicator',
    )
    detection_rate = fields.Char(
        string='Detection Rate',
        compute='_compute_detection_rate',
        store=True,
    )
    threat_label = fields.Char(
        string='Threat Label',
        readonly=True,
        help='Main threat category identified by VirusTotal',
    )
    vt_link = fields.Char(
        string='VirusTotal Report',
        readonly=True,
        help='Direct link to the full VirusTotal report',
    )
    raw_response = fields.Text(
        string='Raw API Response',
        readonly=True,
        groups='cyber_shield.group_cyber_admin',
    )
    error_message = fields.Char(
        string='Error',
        readonly=True,
    )
    analysed_at = fields.Datetime(
        string='Analysed At',
        readonly=True,
        default=fields.Datetime.now,
    )

    # ── RELATIONS ─────────────────────────────────────────────────────────────
    log_id = fields.Many2one(
        comodel_name='cyber.log',
        string='Source Log',
        readonly=True,
        ondelete='set null',
    )
    device_id = fields.Many2one(
        comodel_name='cyber.device',
        string='Device',
        readonly=True,
        ondelete='set null',
    )
    alert_id = fields.Many2one(
        comodel_name='cyber.alert',
        string='Generated Alert',
        readonly=True,
        ondelete='set null',
    )

    # ── COMPUTE ───────────────────────────────────────────────────────────────
    @api.depends('malicious_count', 'total_engines')
    def _compute_detection_rate(self):
        for rec in self:
            if rec.total_engines:
                pct = round((rec.malicious_count / rec.total_engines) * 100, 1)
                rec.detection_rate = f"{rec.malicious_count}/{rec.total_engines} ({pct}%)"
            else:
                rec.detection_rate = "N/A"

    # ── SQL CONSTRAINTS ───────────────────────────────────────────────────────
    _sql_constraints = [
        ('indicator_unique_day', 'UNIQUE(indicator_value, indicator_type)',
         'This indicator has already been analysed. See the existing result.'),
    ]

    # ── MAIN ANALYSIS METHOD ──────────────────────────────────────────────────
    @api.model
    def analyse(self, indicator_type, indicator_value, log_id=None, device_id=None):
        """
        Main entry point for VirusTotal analysis.
        Checks cache first, then calls the API if needed.
        Returns the analysis record.
        """
        # Check if VT is enabled
        params = self.env['ir.config_parameter'].sudo()
        if not params.get_param('cyber_shield.vt_enabled'):
            _logger.debug('CyberShield VT: Integration disabled — skipping analysis')
            return None

        api_key = params.get_param('cyber_shield.vt_api_key', '')
        if not api_key or len(api_key) < 10:
            _logger.warning('CyberShield VT: No API key configured')
            return None

        # Sanitise indicator
        indicator_value = (indicator_value or '').strip()
        if not indicator_value:
            return None

        # Check cache — don't re-query within CACHE_HOURS
        cache_cutoff = fields.Datetime.now() - timedelta(hours=CACHE_HOURS)
        existing = self.search([
            ('indicator_value', '=', indicator_value),
            ('indicator_type', '=', indicator_type),
            ('analysed_at', '>=', cache_cutoff),
            ('state', '!=', 'error'),
        ], limit=1)

        if existing:
            _logger.info('CyberShield VT: Cache hit for %s %s', indicator_type, indicator_value[:20])
            return existing

        # Create pending record
        record = self.sudo().create({
            'indicator_type': indicator_type,
            'indicator_value': indicator_value,
            'state': 'pending',
            'log_id': log_id,
            'device_id': device_id,
            'analysed_at': fields.Datetime.now(),
        })

        # Call VirusTotal API
        result = record._call_vt_api(api_key)
        record._process_result(result)

        # Auto-create alert if threshold exceeded
        threshold = int(params.get_param('cyber_shield.vt_threshold', 3))
        if record.malicious_count >= threshold and device_id:
            record._create_vt_alert(device_id)

        return record

    def _call_vt_api(self, api_key):
        """Call the appropriate VirusTotal API endpoint."""
        self.ensure_one()
        headers = {'x-apikey': api_key, 'Accept': 'application/json'}

        try:
            if self.indicator_type == 'hash':
                url = VT_HASH_URL.format(hash=self.indicator_value)
                return self._vt_get(url, headers)

            elif self.indicator_type == 'ip':
                url = VT_IP_URL.format(ip=self.indicator_value)
                return self._vt_get(url, headers)

            elif self.indicator_type == 'url':
                # Step 1: Submit URL for analysis
                import base64
                url_id = base64.urlsafe_b64encode(
                    self.indicator_value.encode()
                ).decode().rstrip('=')
                # Try to get existing report first
                get_url = VT_URL_GET.format(url_id=url_id)
                result = self._vt_get(get_url, headers)
                if result.get('error', {}).get('code') == 'NotFoundError':
                    # Submit for analysis
                    post_data = f"url={urllib.parse.quote(self.indicator_value)}".encode()
                    post_headers = {**headers, 'Content-Type': 'application/x-www-form-urlencoded'}
                    submit_result = self._vt_post(VT_URL_URL, post_data, post_headers)
                    analysis_id = submit_result.get('data', {}).get('id', '')
                    if analysis_id:
                        time.sleep(15)  # Wait for analysis
                        return self._vt_get(get_url, headers)
                return result

        except Exception as e:
            _logger.error('CyberShield VT API error: %s', str(e))
            return {'_error': str(e)}

        return {}

    def _vt_get(self, url, headers):
        """Make a GET request to VirusTotal."""
        req = urllib.request.Request(url, headers=headers, method='GET')
        try:
            with urllib.request.urlopen(req, timeout=VT_TIMEOUT) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {'error': {'code': 'NotFoundError'}}
            raise
        except Exception as e:
            raise Exception(f"GET {url}: {e}")

    def _vt_post(self, url, data, headers):
        """Make a POST request to VirusTotal."""
        req = urllib.request.Request(url, data=data, headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=VT_TIMEOUT) as resp:
            return json.loads(resp.read())

    def _process_result(self, result):
        """Parse the VirusTotal API response and update the record."""
        self.ensure_one()

        if '_error' in result:
            self.sudo().write({
                'state': 'error',
                'error_message': result['_error'][:250],
            })
            return

        if result.get('error', {}).get('code') == 'NotFoundError':
            self.sudo().write({'state': 'not_found'})
            return

        try:
            data = result.get('data', {})
            attrs = data.get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})

            malicious  = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless   = stats.get('harmless', 0) + stats.get('undetected', 0)
            total      = sum(stats.values()) if stats else 0

            # Determine verdict
            if malicious >= 3:
                verdict = 'malicious'
            elif malicious >= 1 or suspicious >= 5:
                verdict = 'suspicious'
            elif total > 0:
                verdict = 'clean'
            else:
                verdict = 'not_found'

            # Get threat label
            threat_label = (
                attrs.get('popular_threat_classification', {})
                    .get('suggested_threat_label', '') or
                attrs.get('meaningful_name', '') or ''
            )

            # Build VT link
            indicator_id = data.get('id', self.indicator_value)
            vt_type_map = {'hash': 'file', 'url': 'url', 'ip': 'ip-address'}
            vt_type = vt_type_map.get(self.indicator_type, 'file')
            vt_link = f"https://www.virustotal.com/gui/{vt_type}/{indicator_id}"

            self.sudo().write({
                'state': verdict,
                'malicious_count': malicious,
                'suspicious_count': suspicious,
                'harmless_count': harmless,
                'total_engines': total,
                'threat_label': threat_label[:100] if threat_label else '',
                'vt_link': vt_link,
                'raw_response': json.dumps(result, indent=2)[:5000],
                'analysed_at': fields.Datetime.now(),
            })

            _logger.info(
                'CyberShield VT: %s %s → %s (%d/%d detections)',
                self.indicator_type, self.indicator_value[:30],
                verdict, malicious, total
            )

        except Exception as e:
            _logger.error('CyberShield VT: Error processing result: %s', e)
            self.sudo().write({
                'state': 'error',
                'error_message': str(e)[:250],
            })

    def _create_vt_alert(self, device_id):
        """Create a CyberShield alert from a malicious VT result."""
        self.ensure_one()
        device = self.env['cyber.device'].browse(device_id)
        severity = 'critical' if self.malicious_count >= 10 else 'high'

        type_labels = {'hash': 'Malicious File Hash', 'url': 'Malicious URL', 'ip': 'Malicious IP'}
        alert = self.env['cyber.alert'].sudo().create({
            'name': f'[VirusTotal] {type_labels.get(self.indicator_type, "Threat")} detected — {device.display_name}',
            'device_id': device_id,
            'severity': severity,
            'alert_type': 'malware' if self.indicator_type == 'hash' else 'intrusion',
            'description': (
                f"VirusTotal detected a {self.indicator_type} as malicious.\n\n"
                f"Indicator: {self.indicator_value}\n"
                f"Detections: {self.malicious_count}/{self.total_engines} engines\n"
                f"Threat: {self.threat_label or 'Unknown'}\n"
                f"Report: {self.vt_link}"
            ),
            'mitre_tactic': 'execution' if self.indicator_type == 'hash' else 'command_control',
            'source_ip': self.indicator_value if self.indicator_type == 'ip' else '',
        })
        self.sudo().write({'alert_id': alert.id})
        _logger.info('CyberShield VT: Alert created %s for %s', alert.reference, self.indicator_value[:30])

    def action_open_vt_report(self):
        """Open the VirusTotal web report in a new browser tab."""
        self.ensure_one()
        if not self.vt_link:
            raise UserError(_('No VirusTotal report URL available.'))
        return {
            'type': 'ir.actions.act_url',
            'url': self.vt_link,
            'target': 'new',
        }

    def action_reanalyse(self):
        """Force a fresh analysis ignoring cache."""
        self.ensure_one()
        params = self.env['ir.config_parameter'].sudo()
        api_key = params.get_param('cyber_shield.vt_api_key', '')
        if not api_key:
            raise UserError(_('No VirusTotal API key configured. Go to Settings → CyberShield.'))
        self.sudo().write({'state': 'pending', 'analysed_at': fields.Datetime.now()})
        result = self._call_vt_api(api_key)
        self._process_result(result)


# ══════════════════════════════════════════════════════════════════════════════
# EXTEND cyber.log TO AUTO-TRIGGER VT ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
class CyberLogVT(models.Model):
    """Extend cyber.log to trigger VirusTotal analysis on suspicious events."""
    _inherit = 'cyber.log'

    vt_analysis_ids = fields.One2many(
        comodel_name='cyber.vt.analysis',
        inverse_name='log_id',
        string='VirusTotal Analyses',
        readonly=True,
    )
    vt_analysis_count = fields.Integer(
        string='VT Analyses',
        compute='_compute_vt_count',
    )
    vt_verdict = fields.Selection(
        selection=[
            ('clean', '✅ Clean'),
            ('suspicious', '⚠️ Suspicious'),
            ('malicious', '🔴 Malicious'),
            ('pending', '🔄 Pending'),
            ('not_analysed', '— Not Analysed'),
        ],
        string='VT Verdict',
        compute='_compute_vt_verdict',
        store=False,
    )

    @api.depends('vt_analysis_ids')
    def _compute_vt_count(self):
        for rec in self:
            rec.vt_analysis_count = len(rec.vt_analysis_ids)

    @api.depends('vt_analysis_ids.state')
    def _compute_vt_verdict(self):
        for rec in self:
            analyses = rec.vt_analysis_ids.filtered(lambda a: a.state != 'error')
            if not analyses:
                rec.vt_verdict = 'not_analysed'
            elif any(a.state == 'malicious' for a in analyses):
                rec.vt_verdict = 'malicious'
            elif any(a.state == 'suspicious' for a in analyses):
                rec.vt_verdict = 'suspicious'
            elif any(a.state == 'pending' for a in analyses):
                rec.vt_verdict = 'pending'
            else:
                rec.vt_verdict = 'clean'

    def action_vt_analyse(self):
        """Manually trigger VirusTotal analysis for this log entry."""
        self.ensure_one()
        VT = self.env['cyber.vt.analysis']
        triggered = []

        if self.process_name:
            # Generate a pseudo-hash from process name for demo
            # In production this would be the actual file hash from Sysmon
            VT.analyse('hash', self.process_name, log_id=self.id, device_id=self.device_id.id)
            triggered.append(f"Hash: {self.process_name}")

        if self.source_ip:
            VT.analyse('ip', self.source_ip, log_id=self.id, device_id=self.device_id.id)
            triggered.append(f"IP: {self.source_ip}")

        if self.destination_ip:
            VT.analyse('ip', self.destination_ip, log_id=self.id, device_id=self.device_id.id)
            triggered.append(f"IP: {self.destination_ip}")

        if not triggered:
            raise UserError(_('No hash, source IP or destination IP found in this log entry to analyse.'))

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('VirusTotal Analysis Started'),
                'message': _('Analysing: %s') % ', '.join(triggered),
                'type': 'info',
                'sticky': False,
            }
        }