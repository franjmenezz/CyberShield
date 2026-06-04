# ==============================================================================
# CyberShield — Windows Agent Installer v1.1.0
# ==============================================================================
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.
#
# DESCRIPTION:
#   Installs and configures the CyberShield agent on Windows 10/11.
#   This script:
#     1. Installs Sysmon with CyberShield config
#     2. Installs Wazuh Agent (optional)
#     3. Downloads sqlite3.exe for browser history monitoring
#     4. Configures the CyberShield event forwarder (Scheduled Task at startup)
#     5. Installs the vulnerability scanner (Scheduled Task daily at 02:00)
#     6. Registers the device with the CyberShield API
#
# REQUIREMENTS:
#   - Windows 10/11 or Windows Server 2019/2022
#   - PowerShell 5.1+ (run as Administrator)
#   - vuln_scanner.ps1 in the same folder as this script
#
# USAGE:
#   .\install_agent.ps1 `
#     -ServerURL "http://192.168.1.45:8069" `
#     -AgentToken "your-agent-token-here" `
#     -DeviceName "Diseno EQ1"
#
# ==============================================================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]  [string]$ServerURL,
    [Parameter(Mandatory=$true)]  [string]$AgentToken,
    [Parameter(Mandatory=$true)]  [string]$DeviceName,
    [Parameter(Mandatory=$false)] [string]$WazuhManagerIP = "",
    [Parameter(Mandatory=$false)] [switch]$SkipWazuh  = $false,
    [Parameter(Mandatory=$false)] [switch]$SkipSysmon = $false
)

# ── CONFIGURATION ──────────────────────────────────────────────────────────────
$CS_VERSION      = "1.1.0"
$CS_SERVICE_NAME = "CyberShieldAgent"
$CS_VULN_TASK    = "CyberShieldVulnScanner"
$CS_INSTALL_DIR  = "C:\Program Files\CyberShield"
$CS_LOG_DIR      = "C:\ProgramData\CyberShield\logs"
$CS_CONFIG_FILE  = "C:\ProgramData\CyberShield\config.json"
$WAZUH_VERSION   = "4.7.3"
$SYSMON_URL      = "https://download.sysinternals.com/files/Sysmon.zip"
$WAZUH_MSI_URL   = "https://packages.wazuh.com/4.x/windows/wazuh-agent-${WAZUH_VERSION}-1.msi"
$SQLITE3_URL     = "https://www.sqlite.org/2024/sqlite-tools-win-x64-3450300.zip"

# ── LOGGING ────────────────────────────────────────────────────────────────────
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
    if (!(Test-Path $CS_LOG_DIR)) { New-Item -ItemType Directory -Path $CS_LOG_DIR -Force | Out-Null }
    "[$timestamp] [$Level] $Message" | Out-File -FilePath "$CS_LOG_DIR\install.log" -Append -Encoding UTF8
}

function Write-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor DarkMagenta
    Write-Host "  ║       🛡️  CyberShield Agent Installer v1.1.0         ║" -ForegroundColor DarkMagenta
    Write-Host "  ║   Copyright (c) 2025 Francisco Jose Jimenez Pozo   ║" -ForegroundColor DarkMagenta
    Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor DarkMagenta
    Write-Host ""
}

# ── VALIDATE INPUTS ────────────────────────────────────────────────────────────
function Validate-Inputs {
    Write-CS "Validating installation parameters..."
    if ($ServerURL -notmatch '^https?://') { Write-CS "ServerURL must start with http:// or https://" "ERROR"; exit 1 }
    if ($AgentToken.Length -lt 32)         { Write-CS "AgentToken appears invalid (too short)" "ERROR"; exit 1 }
    if ($DeviceName.Length -lt 2)          { Write-CS "DeviceName is too short" "ERROR"; exit 1 }
    Write-CS "Parameters validated successfully" "SUCCESS"
}

# ── SYSTEM INFO ────────────────────────────────────────────────────────────────
function Get-SystemInfo {
    Write-CS "Collecting system information..."
    $os  = Get-WmiObject Win32_OperatingSystem
    $cs  = Get-WmiObject Win32_ComputerSystem
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
    if (!(Test-Path $CS_INSTALL_DIR)) { New-Item -ItemType Directory -Path $CS_INSTALL_DIR -Force | Out-Null }

    $zipPath = "$env:TEMP\Sysmon.zip"
    try {
        Write-CS "Downloading Sysmon from Microsoft Sysinternals..."
        Invoke-WebRequest -Uri $SYSMON_URL -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $CS_INSTALL_DIR -Force
        Remove-Item $zipPath -Force
    } catch {
        Write-CS "Failed to download Sysmon: $_" "WARNING"
        return $false
    }

    $sysmonConfig = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
      </ProcessCreate>
    </RuleGroup>
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
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
        <TargetImage condition="end with">winlogon.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@
    $sysmonConfig | Out-File -FilePath "$CS_INSTALL_DIR\sysmon_config.xml" -Encoding UTF8
    $sysmonPath = "$CS_INSTALL_DIR\Sysmon64.exe"
    if (Test-Path $sysmonPath) {
        & $sysmonPath -accepteula -i "$CS_INSTALL_DIR\sysmon_config.xml" | Out-Null
        Write-CS "Sysmon installed successfully" "SUCCESS"
        return $true
    } else {
        Write-CS "Sysmon64.exe not found after extraction" "WARNING"
        return $false
    }
}

# ── INSTALL SQLITE3 ────────────────────────────────────────────────────────────
function Install-Sqlite3 {
    Write-CS "Downloading sqlite3 for browser history monitoring..."
    $sqlite3Path = "$CS_INSTALL_DIR\sqlite3.exe"
    if (Test-Path $sqlite3Path) { Write-CS "sqlite3 already present" "SUCCESS"; return $true }
    if (!(Test-Path $CS_INSTALL_DIR)) { New-Item -ItemType Directory -Path $CS_INSTALL_DIR -Force | Out-Null }

    $zipPath    = "$env:TEMP\sqlite3.zip"
    $extractDir = "$env:TEMP\sqlite3_extract"
    try {
        Invoke-WebRequest -Uri $SQLITE3_URL -OutFile $zipPath -UseBasicParsing -TimeoutSec 30
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
        $found = Get-ChildItem -Path $extractDir -Filter "sqlite3.exe" -Recurse | Select-Object -First 1
        if ($found) {
            Copy-Item $found.FullName -Destination $sqlite3Path -Force
            Write-CS "sqlite3.exe installed at $sqlite3Path" "SUCCESS"
            return $true
        } else {
            Write-CS "sqlite3.exe not found in downloaded archive" "WARNING"
            return $false
        }
    } catch {
        Write-CS "Failed to download sqlite3: $_" "WARNING"
        return $false
    } finally {
        Remove-Item $zipPath    -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ── INSTALL WAZUH AGENT ────────────────────────────────────────────────────────
function Install-WazuhAgent {
    Write-CS "Downloading Wazuh Agent $WAZUH_VERSION..."
    $msiPath = "$env:TEMP\wazuh-agent.msi"
    try {
        Invoke-WebRequest -Uri $WAZUH_MSI_URL -OutFile $msiPath -UseBasicParsing
    } catch {
        Write-CS "Failed to download Wazuh Agent: $_" "ERROR"; return $false
    }
    $wazuhArgs = "/i `"$msiPath`" /quiet"
    if ($WazuhManagerIP) { $wazuhArgs += " WAZUH_MANAGER=`"$WazuhManagerIP`"" }
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

    if (!(Test-Path "C:\ProgramData\CyberShield")) {
        New-Item -ItemType Directory -Path "C:\ProgramData\CyberShield" -Force | Out-Null
    }

    @{
        version       = $CS_VERSION
        server_url    = $ServerURL
        agent_token   = $AgentToken
        device_name   = $DeviceName
        hostname      = $SysInfo.Hostname
        ip_address    = $SysInfo.IPAddress
        mac_address   = $SysInfo.MACAddress
        os            = $SysInfo.OS
        poll_interval = 30
        log_dir       = $CS_LOG_DIR
        installed_at  = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    } | ConvertTo-Json -Depth 3 | Out-File -FilePath $CS_CONFIG_FILE -Encoding UTF8

    $forwarderScript = @'
# CyberShield Event Forwarder Service
# Copyright (c) 2025 Francisco Jose Jimenez Pozo — All rights reserved.

$config  = Get-Content "C:\ProgramData\CyberShield\config.json" | ConvertFrom-Json
$logFile = "$($config.log_dir)\forwarder.log"

function Log-Message { param([string]$msg, [string]$level = "INFO")
    "[$( Get-Date -Format 'yyyy-MM-dd HH:mm:ss')][$level] $msg" |
        Out-File -FilePath $logFile -Append -Encoding UTF8 }

function Send-Event { param([hashtable]$eventData)
    $body      = $eventData | ConvertTo-Json -Compress
    $hmac      = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key  = [System.Text.Encoding]::UTF8.GetBytes($config.agent_token)
    $signature = [BitConverter]::ToString(
        $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($body))
    ).Replace("-","").ToLower()
    try {
        $r = Invoke-RestMethod -Uri "$($config.server_url)/cybershield/api/v1/event" `
            -Method POST -Body $body -TimeoutSec 10 `
            -Headers @{ "X-CyberShield-Token"=$config.agent_token; "X-CyberShield-Signature"=$signature; "Content-Type"="application/json" }
        if ($r.success) { Log-Message "Sent: $($eventData.event_type)" }
    } catch { Log-Message "Error sending event: $_" "ERROR" } }

function Map-Type { param([int]$id)
    @{4624="login";4625="login_failed";4634="logout";4648="login";
      4672="privilege_escalation";4688="process_created";4697="service_started";
      4698="config_changed";4719="config_changed";4720="user_created";
      4726="user_deleted";4728="user_modified";4732="user_modified";
      4740="login_failed";7036="service_started";7040="config_changed";
      4663="file_access";4670="file_modified"}[$id] ?? "other" }

function Get-Sev { param([int]$id)
    if ($id -in @(4624,4625,4648,4672,4698,4720,4726,4728,4732)) { return "critical" }
    if ($id -in @(4634,4647,4688,4697,4740,7036,7040)) { return "high" }
    return "medium" }

Log-Message "CyberShield Forwarder started — $($config.device_name)"

while ($true) {
    try {
        $evts = Get-WinEvent -LogName Security -MaxEvents 50 `
            -FilterXPath "*[System[EventID>=4624 and EventID<=4740]]" -ErrorAction SilentlyContinue
        foreach ($e in $evts) {
            if ($e.Id -in @(4624,4625,4634,4648,4672,4688,4697,4698,4719,4720,4726,4728,4732,4740)) {
                Send-Event @{
                    event_type    = Map-Type $e.Id
                    severity      = Get-Sev $e.Id
                    description   = "$($e.Id): $($e.Message.Substring(0,[Math]::Min(500,$e.Message.Length)))"
                    user_name     = $e.Properties[5]?.Value ?? ""
                    source_ip     = $e.Properties[18]?.Value ?? ""
                    wazuh_rule_id = "WIN-$($e.Id)"
                    raw_data      = $e.Id.ToString()
                }
            }
        }
        $rdp = qwinsta 2>$null | Where-Object { $_ -match "Active" }
        if ($rdp) { Send-Event @{ event_type="remote_access"; severity="high";
            description="Active RDP session detected"; raw_data=($rdp|Out-String).Trim() } }
    } catch { Log-Message "Loop error: $_" "ERROR" }
    Start-Sleep -Seconds $config.poll_interval
}
'@
    $forwarderScript | Out-File -FilePath "$CS_INSTALL_DIR\forwarder.ps1" -Encoding UTF8

    $action    = New-ScheduledTaskAction -Execute "PowerShell.exe" `
        -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$CS_INSTALL_DIR\forwarder.ps1`""
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 0) -RestartCount 3
    Register-ScheduledTask -TaskName $CS_SERVICE_NAME -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description "CyberShield Event Forwarder" -Force | Out-Null
    Write-CS "Forwarder scheduled task registered (runs at startup)" "SUCCESS"
}

# ── INSTALL VULN SCANNER ───────────────────────────────────────────────────────
function Install-VulnScanner {
    Write-CS "Installing CyberShield Vulnerability Scanner..."
    $scannerSrc = "$PSScriptRoot\vuln_scanner.ps1"
    $scannerDst = "$CS_INSTALL_DIR\vuln_scanner.ps1"

    if (Test-Path $scannerSrc) {
        Copy-Item $scannerSrc -Destination $scannerDst -Force
        Write-CS "vuln_scanner.ps1 copied to $CS_INSTALL_DIR" "SUCCESS"
    } else {
        Write-CS "vuln_scanner.ps1 not found next to installer — skipping" "WARNING"
        return $false
    }

    $scanArgs  = "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass " +
                 "-File `"$scannerDst`" -ServerURL `"$ServerURL`" -AgentToken `"$AgentToken`""
    $action    = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $scanArgs
    $trigger   = New-ScheduledTaskTrigger -Daily -At "02:00"
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -RestartCount 2
    Register-ScheduledTask -TaskName $CS_VULN_TASK -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description "CyberShield Vuln Scanner" -Force | Out-Null
    Write-CS "Vulnerability scanner scheduled daily at 02:00" "SUCCESS"

    Write-CS "Running initial vulnerability scan now (may take a few minutes)..."
    Start-ScheduledTask -TaskName $CS_VULN_TASK
    return $true
}

# ── REGISTER DEVICE WITH API ───────────────────────────────────────────────────
function Register-Device {
    param([hashtable]$SysInfo)
    Write-CS "Registering device with CyberShield server..."
    $body = @{
        hostname=($SysInfo.Hostname); os=($SysInfo.OS); os_version=($SysInfo.OSVersion)
        ip_address=($SysInfo.IPAddress); mac_address=($SysInfo.MACAddress)
        manufacturer=($SysInfo.Manufacturer); model=($SysInfo.Model)
        device_name=$DeviceName; agent_version=$CS_VERSION
    } | ConvertTo-Json
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($AgentToken)
    $sig = [BitConverter]::ToString($hmac.ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($body))).Replace("-","").ToLower()
    try {
        $r = Invoke-RestMethod -Uri "$ServerURL/cybershield/api/v1/device" -Method GET -TimeoutSec 15 `
            -Headers @{ "X-CyberShield-Token"=$AgentToken; "X-CyberShield-Signature"=$sig; "Content-Type"="application/json" }
        Write-CS "Device registered: $($r.name) [UID: $($r.device_uid)]" "SUCCESS"
        return $true
    } catch {
        Write-CS "Could not reach server (will retry on service start): $_" "WARNING"
        return $false
    }
}

# ── VERIFY INSTALLATION ────────────────────────────────────────────────────────
function Verify-Installation {
    Write-CS "Verifying installation..."
    $checks = @(
        @{ Name="Config file";       Path=$CS_CONFIG_FILE;                    Type="File" },
        @{ Name="Forwarder script";  Path="$CS_INSTALL_DIR\forwarder.ps1";    Type="File" },
        @{ Name="sqlite3.exe";       Path="$CS_INSTALL_DIR\sqlite3.exe";      Type="File" },
        @{ Name="Vuln scanner";      Path="$CS_INSTALL_DIR\vuln_scanner.ps1"; Type="File" },
        @{ Name="Log directory";     Path=$CS_LOG_DIR;                         Type="Dir"  },
        @{ Name="Forwarder task";    Check={ Get-ScheduledTask -TaskName $CS_SERVICE_NAME -ErrorAction SilentlyContinue }; Type="Task" },
        @{ Name="Vuln scanner task"; Check={ Get-ScheduledTask -TaskName $CS_VULN_TASK    -ErrorAction SilentlyContinue }; Type="Task" }
    )
    $allGood = $true
    foreach ($c in $checks) {
        $ok = if ($c.Type -in "File","Dir") { Test-Path $c.Path }
              else { $null -ne (& $c.Check) }
        Write-CS "$(if ($ok){'OK'}else{'FAIL'}) $($c.Name)" $(if ($ok){"SUCCESS"}else{"WARNING"})
        if (!$ok) { $allGood = $false }
    }
    return $allGood
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
Write-Banner
Validate-Inputs

$sysInfo = Get-SystemInfo
Write-CS "Device: $($sysInfo.Hostname) | OS: $($sysInfo.OS) | IP: $($sysInfo.IPAddress)"

if (!$SkipSysmon) { Install-Sysmon | Out-Null }
if (!$SkipWazuh -and $WazuhManagerIP) { Install-WazuhAgent | Out-Null }
Install-Sqlite3
Install-ForwarderService -SysInfo $sysInfo
Install-VulnScanner
Register-Device -SysInfo $sysInfo | Out-Null

if (Verify-Installation) {
    Write-CS "" "SUCCESS"
    Write-CS "  CyberShield Agent v$CS_VERSION installed successfully!" "SUCCESS"
    Write-CS "  Device '$DeviceName' is now protected." "SUCCESS"
    Write-CS "  Forwarder: active now + at every startup" "SUCCESS"
    Write-CS "  Vuln scan: running now + daily at 02:00" "SUCCESS"
} else {
    Write-CS "Installation completed with warnings. Check: $CS_LOG_DIR\install.log" "WARNING"
}

# Start forwarder immediately
Write-CS "Starting CyberShield forwarder..."
Start-ScheduledTask -TaskName $CS_SERVICE_NAME
Write-CS "Done! CyberShield is active." "SUCCESS"
