# ==============================================================================
# CyberShield — Windows Agent Installer
# ==============================================================================
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.
#
# DESCRIPTION:
#   Installs and configures the CyberShield agent on Windows 10/11.
#   This script:
#     1. Installs Wazuh Agent
#     2. Installs Sysmon with CyberShield config
#     3. Configures the CyberShield event forwarder service
#     4. Registers the device with the CyberShield API
#
# REQUIREMENTS:
#   - Windows 10/11 or Windows Server 2019/2022
#   - PowerShell 5.1+ (run as Administrator)
#   - Internet access to CyberShield server
#
# USAGE:
#   .\install_agent.ps1 `
#     -ServerURL "https://cybershield.yourcompany.com" `
#     -AgentToken "your-agent-token-here" `
#     -DeviceName "Diseño EQ1"
#
# ==============================================================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerURL,

    [Parameter(Mandatory=$true)]
    [string]$AgentToken,

    [Parameter(Mandatory=$true)]
    [string]$DeviceName,

    [Parameter(Mandatory=$false)]
    [string]$WazuhManagerIP = "",

    [Parameter(Mandatory=$false)]
    [switch]$SkipWazuh = $false,

    [Parameter(Mandatory=$false)]
    [switch]$SkipSysmon = $false
)

# ── CONFIGURATION ──────────────────────────────────────────────────────────────
$CS_VERSION       = "1.0.0"
$CS_SERVICE_NAME  = "CyberShieldAgent"
$CS_INSTALL_DIR   = "C:\Program Files\CyberShield"
$CS_LOG_DIR       = "C:\ProgramData\CyberShield\logs"
$CS_CONFIG_FILE   = "C:\ProgramData\CyberShield\config.json"
$WAZUH_VERSION    = "4.7.3"
$SYSMON_URL       = "https://download.sysinternals.com/files/Sysmon.zip"
$WAZUH_MSI_URL    = "https://packages.wazuh.com/4.x/windows/wazuh-agent-${WAZUH_VERSION}-1.msi"

# ── COLORS & LOGGING ───────────────────────────────────────────────────────────
function Write-CS {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        default   { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color

    # Also write to log file
    if (!(Test-Path $CS_LOG_DIR)) { New-Item -ItemType Directory -Path $CS_LOG_DIR -Force | Out-Null }
    "[$timestamp] [$Level] $Message" | Out-File -FilePath "$CS_LOG_DIR\install.log" -Append -Encoding UTF8
}

function Write-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor DarkMagenta
    Write-Host "  ║          🛡️  CyberShield Agent Installer              ║" -ForegroundColor DarkMagenta
    Write-Host "  ║          Version $CS_VERSION — Windows Edition              ║" -ForegroundColor DarkMagenta
    Write-Host "  ║  Copyright (c) 2025 Francisco José Jiménez Pozo    ║" -ForegroundColor DarkMagenta
    Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor DarkMagenta
    Write-Host ""
}

# ── VALIDATE INPUTS ────────────────────────────────────────────────────────────
function Validate-Inputs {
    Write-CS "Validating installation parameters..."

    if ($ServerURL -notmatch '^https?://') {
        Write-CS "ServerURL must start with http:// or https://" "ERROR"
        exit 1
    }
    if ($AgentToken.Length -lt 32) {
        Write-CS "AgentToken appears invalid (too short)" "ERROR"
        exit 1
    }
    if ($DeviceName.Length -lt 2) {
        Write-CS "DeviceName is too short" "ERROR"
        exit 1
    }
    Write-CS "Parameters validated successfully" "SUCCESS"
}

# ── SYSTEM INFO ────────────────────────────────────────────────────────────────
function Get-SystemInfo {
    Write-CS "Collecting system information..."
    $os = Get-WmiObject Win32_OperatingSystem
    $cs = Get-WmiObject Win32_ComputerSystem
    $net = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1
    $mac = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1).MacAddress

    return @{
        Hostname     = $env:COMPUTERNAME
        OS           = $os.Caption
        OSVersion    = $os.Version
        IPAddress    = $net.IPAddress
        MACAddress   = $mac
        Manufacturer = $cs.Manufacturer
        Model        = $cs.Model
    }
}

# ── INSTALL SYSMON ─────────────────────────────────────────────────────────────
function Install-Sysmon {
    Write-CS "Installing Sysmon..."

    $sysmonPath = "$CS_INSTALL_DIR\Sysmon64.exe"
    $sysmonConfigPath = "$CS_INSTALL_DIR\sysmon_config.xml"

    # Create install directory
    if (!(Test-Path $CS_INSTALL_DIR)) {
        New-Item -ItemType Directory -Path $CS_INSTALL_DIR -Force | Out-Null
    }

    # Download Sysmon
    Write-CS "Downloading Sysmon from Microsoft Sysinternals..."
    $zipPath = "$env:TEMP\Sysmon.zip"
    try {
        Invoke-WebRequest -Uri $SYSMON_URL -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $CS_INSTALL_DIR -Force
        Remove-Item $zipPath -Force
    } catch {
        Write-CS "Failed to download Sysmon: $_" "WARNING"
        return $false
    }

    # Write CyberShield Sysmon configuration
    Write-CS "Writing CyberShield Sysmon configuration..."
    $sysmonConfig = @'
<Sysmon schemaversion="4.90">
  <!-- CyberShield Sysmon Configuration v1.0 -->
  <!-- Copyright (c) 2025 Francisco José Jiménez Pozo -->
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <EventFiltering>

    <!-- Process creation -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Network connections -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is">22</DestinationPort>
        <DestinationPort condition="is">23</DestinationPort>
        <DestinationPort condition="is">3389</DestinationPort>
        <DestinationPort condition="is">4444</DestinationPort>
        <DestinationPort condition="is">1433</DestinationPort>
        <DestinationPort condition="is">5432</DestinationPort>
        <DestinationPort condition="is">8069</DestinationPort>
      </NetworkConnect>
    </RuleGroup>

    <!-- File creation in sensitive locations -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\AppData\Roaming\</TargetFilename>
        <TargetFilename condition="contains">\Temp\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.bat</TargetFilename>
        <TargetFilename condition="end with">.vbs</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- USB device connection -->
    <RuleGroup name="" groupRelation="or">
      <RawAccessRead onmatch="include">
        <Device condition="begin with">\Device\HarddiskVolume</Device>
      </RawAccessRead>
    </RuleGroup>

    <!-- Process access (credential dumping detection) -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
        <TargetImage condition="end with">winlogon.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
'@
    $sysmonConfig | Out-File -FilePath $sysmonConfigPath -Encoding UTF8

    # Install Sysmon
    if (Test-Path $sysmonPath) {
        Write-CS "Installing Sysmon with CyberShield config..."
        & $sysmonPath -accepteula -i $sysmonConfigPath | Out-Null
        Write-CS "Sysmon installed successfully" "SUCCESS"
        return $true
    } else {
        Write-CS "Sysmon executable not found after extraction" "WARNING"
        return $false
    }
}

# ── INSTALL WAZUH AGENT ────────────────────────────────────────────────────────
function Install-WazuhAgent {
    Write-CS "Downloading Wazuh Agent $WAZUH_VERSION..."
    $msiPath = "$env:TEMP\wazuh-agent.msi"

    try {
        Invoke-WebRequest -Uri $WAZUH_MSI_URL -OutFile $msiPath -UseBasicParsing
    } catch {
        Write-CS "Failed to download Wazuh Agent: $_" "ERROR"
        return $false
    }

    Write-CS "Installing Wazuh Agent..."
    $wazuhArgs = "/i `"$msiPath`" /quiet"
    if ($WazuhManagerIP) {
        $wazuhArgs += " WAZUH_MANAGER=`"$WazuhManagerIP`""
    }
    $wazuhArgs += " WAZUH_AGENT_NAME=`"$DeviceName`""

    Start-Process msiexec.exe -ArgumentList $wazuhArgs -Wait
    Remove-Item $msiPath -Force -ErrorAction SilentlyContinue

    Write-CS "Wazuh Agent installed successfully" "SUCCESS"
    return $true
}

# ── CREATE CYBERSHIELD FORWARDER SERVICE ───────────────────────────────────────
function Install-ForwarderService {
    param([hashtable]$SysInfo)

    Write-CS "Creating CyberShield event forwarder..."

    # Create config file
    $config = @{
        version      = $CS_VERSION
        server_url   = $ServerURL
        agent_token  = $AgentToken
        device_name  = $DeviceName
        hostname     = $SysInfo.Hostname
        ip_address   = $SysInfo.IPAddress
        mac_address  = $SysInfo.MACAddress
        os           = $SysInfo.OS
        poll_interval = 30
        log_dir      = $CS_LOG_DIR
        installed_at = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    }

    if (!(Test-Path "C:\ProgramData\CyberShield")) {
        New-Item -ItemType Directory -Path "C:\ProgramData\CyberShield" -Force | Out-Null
    }

    $config | ConvertTo-Json -Depth 3 | Out-File -FilePath $CS_CONFIG_FILE -Encoding UTF8

    # Create the PowerShell forwarder script
    $forwarderScript = @'
# CyberShield Event Forwarder Service
# Copyright (c) 2025 Francisco José Jiménez Pozo — All rights reserved.

$config = Get-Content "C:\ProgramData\CyberShield\config.json" | ConvertFrom-Json
$logFile = "$($config.log_dir)\forwarder.log"
$lastEventId = 0

function Log-Message {
    param([string]$msg, [string]$level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$ts][$level] $msg" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

function Send-Event {
    param([hashtable]$eventData)

    $body = $eventData | ConvertTo-Json -Compress
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)

    # Compute HMAC-SHA256 signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($config.agent_token)
    $signature = [BitConverter]::ToString($hmac.ComputeHash($bodyBytes)).Replace("-", "").ToLower()

    $headers = @{
        "X-CyberShield-Token"     = $config.agent_token
        "X-CyberShield-Signature" = $signature
        "Content-Type"            = "application/json"
    }

    try {
        $response = Invoke-RestMethod `
            -Uri "$($config.server_url)/cybershield/api/v1/event" `
            -Method POST `
            -Headers $headers `
            -Body $body `
            -TimeoutSec 10

        if ($response.success) {
            Log-Message "Event sent — Log UID: $($response.log_uid)"
            return $true
        }
    } catch {
        Log-Message "Failed to send event: $_" "ERROR"
        return $false
    }
}

function Get-EventSeverity {
    param([int]$eventId, [string]$message)
    # Map Windows Event IDs to CyberShield severity levels
    $criticalEvents = @(4624, 4625, 4648, 4672, 4698, 4720, 4726, 4728, 4732)
    $highEvents     = @(4634, 4647, 4688, 4697, 4702, 4719, 4740, 7036, 7040)

    if ($criticalEvents -contains $eventId) { return "critical" }
    if ($highEvents -contains $eventId)     { return "high" }
    return "medium"
}

function Map-EventType {
    param([int]$eventId)
    $map = @{
        4624 = "login"; 4625 = "login_failed"; 4634 = "logout"
        4648 = "login"; 4672 = "privilege_escalation"; 4688 = "process_created"
        4697 = "service_started"; 4698 = "config_changed"; 4702 = "config_changed"
        4719 = "config_changed"; 4720 = "user_created"; 4726 = "user_deleted"
        4728 = "user_modified"; 4732 = "user_modified"; 4740 = "login_failed"
        7036 = "service_started"; 7040 = "config_changed"
        4663 = "file_access"; 4656 = "file_access"; 4670 = "file_modified"
    }
    return $map[$eventId] ?? "other"
}

Log-Message "CyberShield Forwarder started — Device: $($config.device_name)"

# Main event loop
while ($true) {
    try {
        # Security events
        $secEvents = Get-WinEvent -LogName Security -MaxEvents 50 `
            -FilterXPath "*[System[EventID>=4624 and EventID<=4740]]" `
            -ErrorAction SilentlyContinue

        foreach ($event in $secEvents) {
            if ($event.Id -in @(4624, 4625, 4634, 4648, 4672, 4688,
                                 4697, 4698, 4702, 4719, 4720, 4726,
                                 4728, 4732, 4740)) {

                $eventData = @{
                    event_type    = Map-EventType $event.Id
                    severity      = Get-EventSeverity $event.Id $event.Message
                    description   = "$($event.Id): $($event.Message.Substring(0, [Math]::Min(500, $event.Message.Length)))"
                    user_name     = $event.Properties[5]?.Value ?? ""
                    source_ip     = $event.Properties[18]?.Value ?? ""
                    wazuh_rule_id = "WIN-$($event.Id)"
                    raw_data      = $event.Id.ToString()
                }
                Send-Event $eventData | Out-Null
            }
        }

        # Check for USB devices (new drives)
        $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[D-Z]:\\$' }
        foreach ($drive in $drives) {
            $usbKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
            if (Test-Path $usbKey) {
                $eventData = @{
                    event_type  = "usb_connected"
                    severity    = "medium"
                    description = "Removable drive detected: $($drive.Root)"
                    raw_data    = $drive.Root
                }
                # Only send once per session (simplified)
            }
        }

        # Check RDP/remote sessions
        $rdpSessions = qwinsta 2>$null | Where-Object { $_ -match "Active" }
        if ($rdpSessions) {
            $eventData = @{
                event_type  = "remote_access"
                severity    = "high"
                description = "Active remote desktop session detected"
                raw_data    = ($rdpSessions | Out-String).Trim()
            }
            Send-Event $eventData | Out-Null
        }

    } catch {
        Log-Message "Forwarder loop error: $_" "ERROR"
    }

    Start-Sleep -Seconds $config.poll_interval
}
'@
    $forwarderScript | Out-File -FilePath "$CS_INSTALL_DIR\forwarder.ps1" -Encoding UTF8

    # Register as scheduled task (runs on startup)
    Write-CS "Registering CyberShield as scheduled task..."
    $action = New-ScheduledTaskAction `
        -Execute "PowerShell.exe" `
        -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$CS_INSTALL_DIR\forwarder.ps1`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 0) -RestartCount 3

    Register-ScheduledTask `
        -TaskName $CS_SERVICE_NAME `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "CyberShield Security Event Forwarder" `
        -Force | Out-Null

    Write-CS "Scheduled task registered successfully" "SUCCESS"
}

# ── REGISTER DEVICE WITH API ───────────────────────────────────────────────────
function Register-Device {
    param([hashtable]$SysInfo)

    Write-CS "Registering device with CyberShield server..."

    $body = @{
        hostname     = $SysInfo.Hostname
        os           = $SysInfo.OS
        os_version   = $SysInfo.OSVersion
        ip_address   = $SysInfo.IPAddress
        mac_address  = $SysInfo.MACAddress
        manufacturer = $SysInfo.Manufacturer
        model        = $SysInfo.Model
        device_name  = $DeviceName
        agent_version = $CS_VERSION
    } | ConvertTo-Json

    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($AgentToken)
    $signature = [BitConverter]::ToString($hmac.ComputeHash($bodyBytes)).Replace("-", "").ToLower()

    try {
        $response = Invoke-RestMethod `
            -Uri "$ServerURL/cybershield/api/v1/device" `
            -Method GET `
            -Headers @{
                "X-CyberShield-Token"     = $AgentToken
                "X-CyberShield-Signature" = $signature
                "Content-Type"            = "application/json"
            } -TimeoutSec 15

        Write-CS "Device registered: $($response.name) [UID: $($response.device_uid)]" "SUCCESS"
        return $true
    } catch {
        Write-CS "Could not reach CyberShield server (will retry on service start): $_" "WARNING"
        return $false
    }
}

# ── VERIFY INSTALLATION ────────────────────────────────────────────────────────
function Verify-Installation {
    Write-CS "Verifying installation..."
    $checks = @(
        @{ Name = "Config file";          Path = $CS_CONFIG_FILE;           Type = "File" },
        @{ Name = "Forwarder script";     Path = "$CS_INSTALL_DIR\forwarder.ps1"; Type = "File" },
        @{ Name = "Log directory";        Path = $CS_LOG_DIR;                Type = "Dir" },
        @{ Name = "Scheduled task";       Check = { Get-ScheduledTask -TaskName $CS_SERVICE_NAME -ErrorAction SilentlyContinue }; Type = "Task" }
    )

    $allGood = $true
    foreach ($check in $checks) {
        $ok = $false
        if ($check.Type -in "File","Dir") {
            $ok = Test-Path $check.Path
        } elseif ($check.Type -eq "Task") {
            $ok = ($null -ne (& $check.Check))
        }
        $status = if ($ok) { "✅" } else { "❌" }
        Write-CS "$status $($check.Name)"
        if (!$ok) { $allGood = $false }
    }
    return $allGood
}

# ── MAIN ───────────────────────────────────────────────────────────────────────
Write-Banner
Validate-Inputs

$sysInfo = Get-SystemInfo
Write-CS "Device: $($sysInfo.Hostname) | OS: $($sysInfo.OS) | IP: $($sysInfo.IPAddress)"

if (!$SkipSysmon) { Install-Sysmon | Out-Null }
if (!$SkipWazuh -and $WazuhManagerIP) { Install-WazuhAgent | Out-Null }
Install-ForwarderService -SysInfo $sysInfo
Register-Device -SysInfo $sysInfo | Out-Null

if (Verify-Installation) {
    Write-CS ""
    Write-CS "═══════════════════════════════════════════════════" "SUCCESS"
    Write-CS "  CyberShield Agent installed successfully!        " "SUCCESS"
    Write-CS "  Device '$DeviceName' is now protected.           " "SUCCESS"
    Write-CS "  Restart required to start the forwarder.        " "SUCCESS"
    Write-CS "═══════════════════════════════════════════════════" "SUCCESS"
} else {
    Write-CS "Installation completed with warnings. Check logs at: $CS_LOG_DIR" "WARNING"
}

# Start forwarder immediately (without waiting for reboot)
Write-CS "Starting CyberShield forwarder..."
Start-ScheduledTask -TaskName $CS_SERVICE_NAME
Write-CS "Forwarder started" "SUCCESS"
