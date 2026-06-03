# ==============================================================================
# CyberShield — Windows Monitoring Agent (Full)
# ==============================================================================
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.
#
# Monitoriza y envía a CyberShield:
#   - Logins / logouts / intentos fallidos
#   - Procesos ejecutados y terminados
#   - Ficheros abiertos / modificados / eliminados
#   - Conexiones de red (origen, destino, puerto)
#   - Dispositivos USB conectados
#   - Aplicaciones activas en cada momento
#   - URLs visitadas en Chrome, Edge y Firefox
#   - Encendido / apagado / bloqueo de sesión
#
# USAGE:
#   .\monitor_agent.ps1 `
#     -ServerURL "https://cybershield.yourcompany.com" `
#     -AgentToken "your-token-here" `
#     -DeviceName "Diseño EQ1"
# ==============================================================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]  [string]$ServerURL,
    [Parameter(Mandatory=$true)]  [string]$AgentToken,
    [Parameter(Mandatory=$true)]  [string]$DeviceName,
    [Parameter(Mandatory=$false)] [int]$PollInterval = 30,
    [Parameter(Mandatory=$false)] [switch]$Debug
)

# ── CONFIGURATION ──────────────────────────────────────────────────────────────
$CS_VERSION    = "1.1.0"
$CS_LOG_DIR    = "C:\ProgramData\CyberShield\logs"
$CS_STATE_FILE = "C:\ProgramData\CyberShield\state.json"
$API_ENDPOINT  = "$ServerURL/cybershield/api/v1/event"

# ── LOGGING ────────────────────────────────────────────────────────────────────
if (!(Test-Path $CS_LOG_DIR)) { New-Item -ItemType Directory -Path $CS_LOG_DIR -Force | Out-Null }
$LogFile = "$CS_LOG_DIR\monitor.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    if ($Debug) { Write-Host $line }
}

# ── HMAC-SHA256 SIGNATURE ──────────────────────────────────────────────────────
function Get-HmacSHA256 {
    param([string]$Key, [string]$Message)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
    return [BitConverter]::ToString($hmac.ComputeHash($bytes)).Replace("-","").ToLower()
}

# ── SEND EVENT ─────────────────────────────────────────────────────────────────
function Send-Event {
    param([hashtable]$EventData)

    $body = $EventData | ConvertTo-Json -Compress -Depth 3
    $signature = Get-HmacSHA256 -Key $AgentToken -Message $body

    try {
        $response = Invoke-RestMethod `
            -Uri $API_ENDPOINT `
            -Method POST `
            -Body $body `
            -ContentType "application/json" `
            -Headers @{
                "X-CyberShield-Token"     = $AgentToken
                "X-CyberShield-Signature" = $signature
            } `
            -TimeoutSec 10 `
            -ErrorAction Stop

        if ($response.success) {
            Write-Log "Event sent: $($EventData.event_type) / $($EventData.severity)"
            return $true
        }
    } catch {
        Write-Log "Failed to send event: $_" "ERROR"
        return $false
    }
}

# ── STATE MANAGEMENT ───────────────────────────────────────────────────────────
function Get-State {
    if (Test-Path $CS_STATE_FILE) {
        try { return Get-Content $CS_STATE_FILE | ConvertFrom-Json }
        catch {}
    }
    return [PSCustomObject]@{
        last_event_ids      = @{}
        known_processes     = @()
        known_usb_drives    = @()
        last_browser_check  = $null
    }
}

function Save-State {
    param($State)
    $State | ConvertTo-Json -Depth 5 | Set-Content -Path $CS_STATE_FILE -Encoding UTF8
}

# ══════════════════════════════════════════════════════════════════════════════
# MONITOR FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. LOGIN / LOGOUT / FAILED LOGIN ──────────────────────────────────────────
function Monitor-AuthEvents {
    param($State)

    $eventMap = @{
        4624 = @{ type = "login";              severity = "medium" }
        4625 = @{ type = "login_failed";       severity = "high" }
        4634 = @{ type = "logout";             severity = "low" }
        4647 = @{ type = "logout";             severity = "low" }
        4648 = @{ type = "login";              severity = "high" }   # Explicit credentials
        4672 = @{ type = "privilege_escalation"; severity = "critical" }
        4800 = @{ type = "other";              severity = "low" }    # Workstation locked
        4801 = @{ type = "login";              severity = "low" }    # Workstation unlocked
        4802 = @{ type = "other";              severity = "low" }    # Screensaver on
        4803 = @{ type = "other";              severity = "low" }    # Screensaver off
    }

    $lastId = $State.last_event_ids.auth ?? 0

    try {
        $events = Get-WinEvent -LogName Security -MaxEvents 50 -ErrorAction SilentlyContinue |
            Where-Object { $eventMap.ContainsKey($_.Id) -and $_.RecordId -gt $lastId } |
            Sort-Object RecordId

        foreach ($ev in $events) {
            $info = $eventMap[$ev.Id]
            $xml = [xml]$ev.ToXml()
            $ns = @{ e = "http://schemas.microsoft.com/win/2004/08/events/event" }

            $user = ($xml.SelectNodes("//e:Data[@Name='TargetUserName']", 
                     ([System.Xml.XmlNamespaceManager]::new($xml.NameTable) | 
                      ForEach-Object { $_.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event"); $_ })) |
                     Select-Object -First 1)?.InnerText ?? ""
            
            $ip = ""
            try {
                $ipNode = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }
                $ip = if ($ipNode) { $ipNode.'#text' } else { "" }
                if ($ip -eq "-" -or $ip -eq "::1" -or $ip -eq "127.0.0.1") { $ip = "" }
            } catch {}

            $userName = ""
            try {
                $userNode = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }
                $userName = if ($userNode) { $userNode.'#text' } else { "" }
            } catch {}

            $descriptions = @{
                4624 = "User login successful"
                4625 = "FAILED login attempt"
                4634 = "User logged out"
                4647 = "User initiated logoff"
                4648 = "Login with explicit credentials (possible lateral movement)"
                4672 = "Special privileges assigned to new logon (admin login)"
                4800 = "Workstation was locked"
                4801 = "Workstation was unlocked"
                4802 = "Screen saver invoked"
                4803 = "Screen saver dismissed"
            }

            Send-Event @{
                event_type  = $info.type
                severity    = $info.severity
                description = "$($descriptions[$ev.Id]) | User: $userName | EventID: $($ev.Id)"
                user_name   = $userName
                source_ip   = $ip
                wazuh_rule_id = "WIN-AUTH-$($ev.Id)"
                raw_data    = $ev.Id.ToString()
            } | Out-Null

            $State.last_event_ids.auth = $ev.RecordId
        }
    } catch {
        Write-Log "Auth monitor error: $_" "ERROR"
    }
}

# ── 2. PROCESS EXECUTION ───────────────────────────────────────────────────────
function Monitor-Processes {
    param($State)

    # Procesos sospechosos que siempre notificar
    $suspiciousProcesses = @(
        "powershell", "cmd", "wscript", "cscript", "mshta", "regsvr32",
        "rundll32", "certutil", "bitsadmin", "net", "netsh", "nmap",
        "mimikatz", "psexec", "wmic", "msiexec", "installutil"
    )

    try {
        $currentProcesses = Get-Process | Select-Object -ExpandProperty Name | Sort-Object -Unique
        $knownProcesses   = $State.known_processes ?? @()

        # Nuevos procesos
        $newProcesses = $currentProcesses | Where-Object { $_ -notin $knownProcesses }

        foreach ($proc in $newProcesses) {
            $isSuspicious = $suspiciousProcesses | Where-Object { $proc -like "*$_*" }
            $severity = if ($isSuspicious) { "high" } else { "low" }

            # Solo enviar procesos nuevos sospechosos o todos si está en modo completo
            if ($isSuspicious -or $Debug) {
                Send-Event @{
                    event_type   = "process_created"
                    severity     = $severity
                    description  = "Process started: $proc"
                    process_name = $proc
                    wazuh_rule_id = "WIN-PROC-NEW"
                } | Out-Null
            }
        }

        # Procesos terminados (solo si eran sospechosos)
        $terminatedProcesses = $knownProcesses | Where-Object { 
            $_ -notin $currentProcesses -and 
            ($suspiciousProcesses | Where-Object { $_ -like "*$__*" })
        }

        foreach ($proc in $terminatedProcesses) {
            Send-Event @{
                event_type   = "process_terminated"
                severity     = "low"
                description  = "Process ended: $proc"
                process_name = $proc
                wazuh_rule_id = "WIN-PROC-END"
            } | Out-Null
        }

        $State.known_processes = $currentProcesses

    } catch {
        Write-Log "Process monitor error: $_" "ERROR"
    }
}

# ── 3. ACTIVE APPLICATIONS ────────────────────────────────────────────────────
function Monitor-ActiveApplications {
    # Enviar resumen de aplicaciones activas cada 5 minutos
    try {
        $apps = Get-Process | Where-Object { $_.MainWindowTitle -ne "" } |
            Select-Object Name, MainWindowTitle |
            Sort-Object Name -Unique

        if ($apps.Count -gt 0) {
            $appList = ($apps | ForEach-Object { "$($_.Name): $($_.MainWindowTitle)" }) -join " | "
            
            Send-Event @{
                event_type  = "other"
                severity    = "info"
                description = "Active applications snapshot: $($appList.Substring(0, [Math]::Min(800, $appList.Length)))"
                wazuh_rule_id = "WIN-APPS-SNAPSHOT"
            } | Out-Null
        }
    } catch {
        Write-Log "Active apps monitor error: $_" "ERROR"
    }
}

# ── 4. BROWSER URL MONITORING ─────────────────────────────────────────────────
function Monitor-BrowserURLs {
    param($State)

    $browsers = @(
        @{
            Name    = "Chrome"
            DBPath  = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
            Query   = "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 20"
        },
        @{
            Name    = "Edge"
            DBPath  = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
            Query   = "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 20"
        },
        @{
            Name    = "Firefox"
            DBPath  = (Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\*.default*\places.sqlite" -ErrorAction SilentlyContinue | Select-Object -First 1)?.FullName
            Query   = "SELECT url, title, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 20"
        }
    )

    foreach ($browser in $browsers) {
        if (!$browser.DBPath -or !(Test-Path $browser.DBPath)) { continue }

        try {
            # Copiar BD porque el navegador la tiene bloqueada
            $tempDB = "$env:TEMP\cs_browser_$($browser.Name).db"
            Copy-Item -Path $browser.DBPath -Destination $tempDB -Force -ErrorAction Stop

            # Usar sqlite3 si está disponible
            $sqlite = "C:\Program Files\CyberShield\sqlite3.exe"
            if (!(Test-Path $sqlite)) {
                Remove-Item $tempDB -Force -ErrorAction SilentlyContinue
                continue
            }

            $results = & $sqlite $tempDB $browser.Query 2>$null

            foreach ($row in $results) {
                $parts = $row -split "\|"
                if ($parts.Count -lt 2) { continue }
                
                $url   = $parts[0]
                $title = $parts[1]

                # Filtrar URLs internas y triviales
                if ($url -match "^(chrome|edge|about|file|data):" ) { continue }
                if ($url -match "localhost|127\.0\.0\.1") { continue }

                # Detectar URLs de riesgo
                $severity = "info"
                $riskPatterns = @("pastebin", "mega.nz", "wetransfer", "temp-mail", 
                                   "guerrillamail", "torrent", "darkweb", "onion")
                if ($riskPatterns | Where-Object { $url -match $_ }) {
                    $severity = "high"
                }

                Send-Event @{
                    event_type  = "network_connection"
                    severity    = $severity
                    description = "[$($browser.Name)] $title | $url"
                    destination_ip = ($url -replace "https?://([^/]+).*", '$1')
                    wazuh_rule_id  = "WIN-BROWSER-$($browser.Name.ToUpper())"
                    raw_data    = $url.Substring(0, [Math]::Min(500, $url.Length))
                } | Out-Null
            }

            Remove-Item $tempDB -Force -ErrorAction SilentlyContinue

        } catch {
            Write-Log "Browser monitor ($($browser.Name)) error: $_" "WARN"
        }
    }
}

# ── 5. USB DEVICE MONITORING ──────────────────────────────────────────────────
function Monitor-USB {
    param($State)

    try {
        $currentDrives = Get-PSDrive -PSProvider FileSystem | 
            Where-Object { $_.Root -match "^[D-Z]:\\" } |
            Select-Object -ExpandProperty Root

        $knownDrives = $State.known_usb_drives ?? @()

        # Nuevas unidades (USB conectado)
        foreach ($drive in $currentDrives) {
            if ($drive -notin $knownDrives) {
                $label = (Get-Volume -DriveLetter $drive[0] -ErrorAction SilentlyContinue)?.FileSystemLabel ?? "Unknown"
                Send-Event @{
                    event_type  = "usb_connected"
                    severity    = "high"
                    description = "USB/Removable drive connected: $drive (Label: $label)"
                    file_path   = $drive
                    wazuh_rule_id = "WIN-USB-CONNECT"
                    mitre_tactic  = "collection"
                    mitre_technique = "T1052"
                } | Out-Null
            }
        }

        # Unidades desconectadas
        foreach ($drive in $knownDrives) {
            if ($drive -notin $currentDrives) {
                Send-Event @{
                    event_type  = "usb_disconnected"
                    severity    = "medium"
                    description = "USB/Removable drive disconnected: $drive"
                    file_path   = $drive
                    wazuh_rule_id = "WIN-USB-DISCONNECT"
                } | Out-Null
            }
        }

        $State.known_usb_drives = $currentDrives

    } catch {
        Write-Log "USB monitor error: $_" "ERROR"
    }
}

# ── 6. NETWORK CONNECTIONS ────────────────────────────────────────────────────
function Monitor-NetworkConnections {
    $suspiciousPorts = @(22, 23, 4444, 6666, 6667, 31337, 1337, 9999, 8888)
    $suspiciousRanges = @("10\.", "172\.(1[6-9]|2[0-9]|3[01])\.", "192\.168\.")

    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "::" }

        foreach ($conn in $connections) {
            $isLocalRange = $suspiciousRanges | Where-Object { $conn.RemoteAddress -match $_ }
            $isSuspiciousPort = $conn.RemotePort -in $suspiciousPorts

            if ($isSuspiciousPort) {
                Send-Event @{
                    event_type       = "network_connection"
                    severity         = "high"
                    description      = "Suspicious outbound connection to port $($conn.RemotePort): $($conn.RemoteAddress)"
                    destination_ip   = $conn.RemoteAddress
                    destination_port = $conn.RemotePort
                    wazuh_rule_id    = "WIN-NET-SUSPICIOUS"
                    mitre_tactic     = "command_control"
                    mitre_technique  = "T1071"
                } | Out-Null
            }
        }
    } catch {
        Write-Log "Network monitor error: $_" "ERROR"
    }
}

# ── 7. FILE SYSTEM CHANGES ────────────────────────────────────────────────────
function Monitor-FileSystem {
    $sensitiveLocations = @(
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Desktop",
        "$env:APPDATA",
        "C:\Windows\System32"
    )

    $suspiciousExtensions = @(".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".msi", ".cmd")

    try {
        foreach ($location in $sensitiveLocations) {
            if (!(Test-Path $location)) { continue }

            # Ficheros modificados en los últimos 2 minutos
            $recentFiles = Get-ChildItem -Path $location -Recurse -ErrorAction SilentlyContinue |
                Where-Object { 
                    !$_.PSIsContainer -and 
                    $_.LastWriteTime -gt (Get-Date).AddMinutes(-2) -and
                    $_.Extension -in $suspiciousExtensions
                } | Select-Object -First 10

            foreach ($file in $recentFiles) {
                Send-Event @{
                    event_type  = "file_modified"
                    severity    = "medium"
                    description = "Suspicious file modified: $($file.FullName)"
                    file_path   = $file.FullName
                    wazuh_rule_id = "WIN-FILE-MOD"
                    mitre_tactic  = "persistence"
                } | Out-Null
            }
        }
    } catch {
        Write-Log "File system monitor error: $_" "ERROR"
    }
}

# ── 8. SYSTEM EVENTS ──────────────────────────────────────────────────────────
function Monitor-SystemEvents {
    param($State)

    $systemEventMap = @{
        6005 = @{ type = "system_boot";     severity = "info";   desc = "System started (Event Log service started)" }
        6006 = @{ type = "system_shutdown"; severity = "info";   desc = "System shut down cleanly" }
        6008 = @{ type = "system_boot";     severity = "high";   desc = "Unexpected system shutdown (possible crash/power loss)" }
        41   = @{ type = "system_boot";     severity = "high";   desc = "System rebooted without clean shutdown (kernel power)" }
        1074 = @{ type = "system_shutdown"; severity = "medium"; desc = "User-initiated system shutdown/restart" }
        7036 = @{ type = "service_started"; severity = "low";    desc = "Service state changed" }
        7040 = @{ type = "config_changed";  severity = "medium"; desc = "Service start type changed" }
    }

    $lastId = $State.last_event_ids.system ?? 0

    try {
        $events = Get-WinEvent -LogName System -MaxEvents 30 -ErrorAction SilentlyContinue |
            Where-Object { $systemEventMap.ContainsKey($_.Id) -and $_.RecordId -gt $lastId } |
            Sort-Object RecordId

        foreach ($ev in $events) {
            $info = $systemEventMap[$ev.Id]
            Send-Event @{
                event_type    = $info.type
                severity      = $info.severity
                description   = "$($info.desc) | EventID: $($ev.Id) | $($ev.Message.Substring(0, [Math]::Min(200, $ev.Message.Length)))"
                wazuh_rule_id = "WIN-SYS-$($ev.Id)"
            } | Out-Null

            $State.last_event_ids.system = $ev.RecordId
        }
    } catch {
        Write-Log "System events monitor error: $_" "ERROR"
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "CyberShield Monitor Agent v$CS_VERSION started — Device: $DeviceName"
Write-Log "Server: $ServerURL | Poll interval: ${PollInterval}s"

# Send startup event
Send-Event @{
    event_type  = "system_boot"
    severity    = "info"
    description = "CyberShield monitoring agent started on $DeviceName (v$CS_VERSION)"
    wazuh_rule_id = "CS-AGENT-START"
} | Out-Null

$cycle = 0

while ($true) {
    $state = Get-State

    try {
        # Every cycle (30s by default)
        Monitor-AuthEvents  -State $state
        Monitor-USB         -State $state
        Monitor-Processes   -State $state
        Monitor-NetworkConnections
        Monitor-SystemEvents -State $state

        # Every 5 minutes (cycle 10)
        if ($cycle % 10 -eq 0) {
            Monitor-ActiveApplications
            Monitor-FileSystem
        }

        # Every 2 minutes (cycle 4)
        if ($cycle % 4 -eq 0) {
            Monitor-BrowserURLs -State $state
        }

        Save-State $state
        $cycle++

    } catch {
        Write-Log "Main loop error: $_" "ERROR"
    }

    Start-Sleep -Seconds $PollInterval
}
