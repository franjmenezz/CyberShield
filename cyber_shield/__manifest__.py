# -*- coding: utf-8 -*-
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.

{
    'name': 'CyberShield',
    'version': '18.0.1.2.0',
    'summary': 'Enterprise SIEM & Endpoint Activity Monitoring for ODOO 18',
    'author': 'Francisco José Jiménez Pozo',
    'website': 'https://github.com/franjmenezz',
    'license': 'Other proprietary',
    'category': 'Security',
    'sequence': 1,
    'depends': ['base', 'mail', 'web'],
    'data': [
        'security/cyber_shield_security.xml',
        'security/ir.model.access.csv',
        'data/cyber_shield_data.xml',
        'data/mail_templates.xml',
        'data/notification_data.xml',
        'views/dashboard_views.xml',
        'views/device_views.xml',
        'views/activity_views.xml',
        'views/log_views.xml',
        'views/alert_views.xml',
        'views/vulnerability_views.xml',
        'views/incident_views.xml',
        'views/report_views.xml',
        'views/notification_views.xml',
        'views/virustotal_views.xml',
        'views/menu_views.xml',
    ],
    'assets': {
        'web.assets_backend': [
            'cyber_shield/static/src/css/cyber_shield.css',
            'cyber_shield/static/src/js/dashboard.js',
        ],
    },
    'installable': True,
    'application': True,
    'auto_install': False,
}
