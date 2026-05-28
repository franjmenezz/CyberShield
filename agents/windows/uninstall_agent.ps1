# ==============================================================================
# CyberShield — Windows Agent Uninstaller
# Copyright (c) 2025 Francisco José Jiménez Pozo — All rights reserved.
# ==============================================================================
#Requires -RunAsAdministrator

$CS_SERVICE_NAME = "CyberShieldAgent"
$CS_INSTALL_DIR  = "C:\Program Files\CyberShield"
$CS_DATA_DIR     = "C:\ProgramData\CyberShield"

Write-Host "[CyberShield] Uninstalling agent..." -ForegroundColor Yellow

# Stop and remove scheduled task
Stop-ScheduledTask -TaskName $CS_SERVICE_NAME -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $CS_SERVICE_NAME -Confirm:$false -ErrorAction SilentlyContinue

# Uninstall Sysmon
$sysmonPath = "$CS_INSTALL_DIR\Sysmon64.exe"
if (Test-Path $sysmonPath) {
    & $sysmonPath -u force 2>$null
}

# Remove files
Remove-Item -Path $CS_INSTALL_DIR -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $CS_DATA_DIR -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[CyberShield] Agent uninstalled successfully." -ForegroundColor Green
