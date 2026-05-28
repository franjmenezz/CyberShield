/** @odoo-module **/
/* CyberShield Dashboard — Copyright (c) 2025 Francisco José Jiménez Pozo */
import { registry } from "@web/core/registry";
import { Component } from "@odoo/owl";

// Dashboard component placeholder — full implementation in Entrega 2
class CyberShieldDashboard extends Component {
    static template = "cyber_shield.Dashboard";
}

registry.category("actions").add("cyber_shield.dashboard", CyberShieldDashboard);
