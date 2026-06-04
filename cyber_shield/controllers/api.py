# -*- coding: utf-8 -*-
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.

"""
CyberShield — Secure REST API Controller
=========================================
Receives security events from Wazuh agents via HTTPS.

Security features:
- HMAC-SHA256 request signature verification
- Agent token authentication (Zero Trust)
- Rate limiting per agent
- Strict input validation and sanitization
- All events logged with integrity hash chaining
"""

import hashlib
import hmac
import json
import logging
import re
import time
from functools import wraps
from collections import defaultdict

from odoo import http, fields
from odoo.http import request, Response

_logger = logging.getLogger(__name__)

# ── RATE LIMITER ──────────────────────────────────────────────────────────────
class RateLimiter:
    """
    Simple in-memory rate limiter.
    Limits: MAX_EVENTS events per WINDOW_SECONDS per agent token.
    """
    MAX_EVENTS = 1000
    WINDOW_SECONDS = 60

    def __init__(self):
        self._buckets = defaultdict(list)

    def is_allowed(self, token: str) -> bool:
        now = time.time()
        window_start = now - self.WINDOW_SECONDS
        bucket = self._buckets[token]
        # Remove old entries
        self._buckets[token] = [t for t in bucket if t > window_start]
        if len(self._buckets[token]) >= self.MAX_EVENTS:
            return False
        self._buckets[token].append(now)
        return True


_rate_limiter = RateLimiter()


# ── INPUT VALIDATORS ──────────────────────────────────────────────────────────
VALID_EVENT_TYPES = {
    'login', 'logout', 'login_failed', 'privilege_escalation', 'remote_access',
    'usb_connected', 'usb_disconnected', 'file_access', 'file_modified',
    'file_deleted', 'process_created', 'process_terminated', 'network_connection',
    'network_blocked', 'port_scan', 'malware_detected', 'policy_violation',
    'config_changed', 'user_created', 'user_deleted', 'user_modified',
    'service_started', 'service_stopped', 'system_boot', 'system_shutdown', 'other',
}
VALID_SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}
IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F:]+)$')
MAX_DESCRIPTION_LEN = 2000
MAX_RAW_DATA_LEN = 10000


def _sanitize_string(value, max_len=255) -> str:
    """Sanitize string input — strip, limit length, remove null bytes."""
    if not isinstance(value, str):
        return ''
    return value.replace('\x00', '').strip()[:max_len]


def _validate_ip(ip: str) -> str:
    """Validate and return IP address or empty string."""
    if not ip:
        return ''
    ip = _sanitize_string(ip, 45)
    return ip if IP_PATTERN.match(ip) else ''


def _validate_port(port) -> int:
    """Validate TCP/UDP port number."""
    try:
        port = int(port)
        return port if 0 <= port <= 65535 else 0
    except (TypeError, ValueError):
        return 0


def _json_error(message: str, code: int = 400) -> Response:
    """Return a standardized JSON error response."""
    body = json.dumps({'success': False, 'error': message})
    return Response(body, status=code, mimetype='application/json')


def _json_ok(data: dict) -> Response:
    """Return a standardized JSON success response."""
    body = json.dumps({'success': True, **data})
    return Response(body, status=200, mimetype='application/json')


# ── CONTROLLER ────────────────────────────────────────────────────────────────
class CyberShieldAPI(http.Controller):
    """
    CyberShield REST API — Wazuh event ingestion endpoint.

    Endpoints:
        POST /cybershield/api/v1/event     — Submit a security event
        GET  /cybershield/api/v1/health    — Health check (no auth required)
        GET  /cybershield/api/v1/device    — Get device info (agent auth required)
    """

    # ── HEALTH CHECK ──────────────────────────────────────────────────────────
    @http.route(
        '/cybershield/api/v1/health',
        type='http',
        auth='none',
        methods=['GET'],
        csrf=False,
    )
    def health_check(self, **kwargs):
        """Public health check endpoint — no authentication required."""
        return _json_ok({'status': 'healthy', 'version': '1.0.0'})

    # ── EVENT INGESTION ───────────────────────────────────────────────────────
    @http.route(
        '/cybershield/api/v1/event',
        type='http',
        auth='none',
        methods=['POST'],
        csrf=False,
    )
    def receive_event(self, **kwargs):
        """
        Receive a security event from a Wazuh agent.

        Required headers:
            X-CyberShield-Token: <agent_token>
            X-CyberShield-Signature: <HMAC-SHA256 of request body>
            Content-Type: application/json

        Required body fields:
            event_type: str
            severity: str
            description: str

        Optional body fields:
            user_name, process_name, file_path,
            source_ip, destination_ip, destination_port,
            mitre_tactic, mitre_technique,
            wazuh_rule_id, wazuh_rule_level, raw_data
        """
        # ── 1. EXTRACT HEADERS ────────────────────────────────────────────────
        agent_token = request.httprequest.headers.get('X-CyberShield-Token', '')
        signature = request.httprequest.headers.get('X-CyberShield-Signature', '')

        if not agent_token or not signature:
            _logger.warning('CyberShield API: Missing authentication headers')
            return _json_error('Missing authentication headers', 401)

        # ── 2. RATE LIMITING ──────────────────────────────────────────────────
        if not _rate_limiter.is_allowed(agent_token):
            _logger.warning('CyberShield API: Rate limit exceeded for token %s...', agent_token[:8])
            return _json_error('Rate limit exceeded. Maximum 1000 events per minute.', 429)

        # ── 3. PARSE BODY ─────────────────────────────────────────────────────
        try:
            raw_body = request.httprequest.get_data(as_text=True)
            if len(raw_body) > 50000:
                return _json_error('Request body too large', 413)
            payload = json.loads(raw_body)
        except (json.JSONDecodeError, Exception):
            return _json_error('Invalid JSON payload', 400)

        # ── 4. VERIFY AGENT TOKEN ─────────────────────────────────────────────
        env = request.env(su=True)
        device = env['cyber.device'].search(
            [('agent_token', '=', agent_token), ('active', '=', True)],
            limit=1
        )
        if not device:
            _logger.warning('CyberShield API: Unknown or inactive agent token %s...', agent_token[:8])
            return _json_error('Invalid agent token', 401)

        # ── 5. VERIFY HMAC SIGNATURE ──────────────────────────────────────────
        expected_sig = hmac.new(
            agent_token.encode('utf-8'),
            raw_body.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            _logger.warning(
                'CyberShield API: Invalid HMAC signature from device %s',
                device.display_name
            )
            return _json_error('Invalid request signature', 401)

        # ── 6. VALIDATE REQUIRED FIELDS ───────────────────────────────────────
        event_type = payload.get('event_type', '')
        if event_type not in VALID_EVENT_TYPES:
            return _json_error(f'Invalid event_type: {event_type}', 400)

        severity = payload.get('severity', 'info')
        if severity not in VALID_SEVERITIES:
            return _json_error(f'Invalid severity: {severity}', 400)

        description = _sanitize_string(payload.get('description', ''), MAX_DESCRIPTION_LEN)
        if not description:
            return _json_error('description is required', 400)

        # ── 7. SANITIZE OPTIONAL FIELDS ───────────────────────────────────────
        log_vals = {
            'device_id': device.id,
            'event_type': event_type,
            'severity': severity,
            'description': description,
            'wazuh_agent_id': _sanitize_string(payload.get('wazuh_agent_id', '')),
            'source_ip': _validate_ip(payload.get('source_ip', '')),
            'destination_ip': _validate_ip(payload.get('destination_ip', '')),
            'destination_port': _validate_port(payload.get('destination_port', 0)),
            'user_name': _sanitize_string(payload.get('user_name', '')),
            'process_name': _sanitize_string(payload.get('process_name', '')),
            'file_path': _sanitize_string(payload.get('file_path', ''), 512),
            'wazuh_rule_id': _sanitize_string(payload.get('wazuh_rule_id', '')),
            'wazuh_rule_level': _validate_port(payload.get('wazuh_rule_level', 0)),
            'mitre_tactic': payload.get('mitre_tactic') if payload.get('mitre_tactic') in {
                'reconnaissance', 'resource_development', 'initial_access', 'execution',
                'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
                'discovery', 'lateral_movement', 'collection', 'command_control',
                'exfiltration', 'impact'
            } else False,
            'mitre_technique': _sanitize_string(payload.get('mitre_technique', ''), 20),
            'raw_data': _sanitize_string(payload.get('raw_data', ''), MAX_RAW_DATA_LEN),
        }

        # ── 8. CREATE LOG ENTRY ───────────────────────────────────────────────
        try:
            log = env['cyber.log'].sudo().create(log_vals)
            # Update device last_seen and agent_status
            device.sudo().write({
                'last_seen': fields.Datetime.now() if hasattr(fields, 'Datetime') else None,
                'agent_status': 'connected',
            })
            _logger.info(
                'CyberShield API: Event [%s/%s] received from %s — Log UID: %s',
                severity.upper(), event_type, device.display_name, log.log_uid
            )
            return _json_ok({
                'log_uid': log.log_uid,
                'event_hash': log.event_hash,
                'alert_created': bool(log.alert_id),
            })
        except Exception as e:
            _logger.error('CyberShield API: Error creating log entry: %s', str(e))
            return _json_error('Internal server error', 500)

    # ── DEVICE INFO ───────────────────────────────────────────────────────────
    @http.route(
        '/cybershield/api/v1/device',
        type='http',
        auth='none',
        methods=['GET'],
        csrf=False,
    )
    def get_device_info(self, **kwargs):
        """Return basic device info for the authenticated agent."""
        agent_token = request.httprequest.headers.get('X-CyberShield-Token', '')
        if not agent_token:
            return _json_error('Missing agent token', 401)

        env = request.env(su=True)
        device = env['cyber.device'].search(
            [('agent_token', '=', agent_token), ('active', '=', True)],
            limit=1
        )
        if not device:
            return _json_error('Invalid agent token', 401)

        return _json_ok({
            'device_uid': device.device_uid,
            'name': device.display_name,
            'device_type': device.device_type,
            'status': device.status,
        })
