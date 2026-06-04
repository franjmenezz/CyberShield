# ==============================================================================
# CyberShield — Windows Vulnerability Scanner v1.0
# ==============================================================================
# Copyright (c) 2025 Francisco José Jiménez Pozo
# All rights reserved. Proprietary and confidential.
#
# DESCRIPTION:
#   Scans installed software and Windows updates against the NVD (NIST) CVE
#   database and reports findings to the CyberShield API.
#
#   What it checks:
#     1. Installed software (registry) vs NVD CVE database
#     2. Missing Windows updates (via Windows Update API)
#     3. Outdated browsers (Chrome, Edge, Firefox)
#     4. Weak configurations (open shares, RDP exposed, etc.)
#     5. Running services with known vulnerabilities
#
# USAGE:
#   .\vuln_scanner.ps1 `
#     -ServerURL "http://192.168.1.45:8069" `
#     -AgentToken "your-token-here"
#
#   Or scheduled automatically by install_agent.ps1 (runs daily at 02:00)
# ==============================================================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]  [string]$ServerURL,
    [Parameter(Mandatory=$true)]  [string]$AgentToken,
    [Parameter(Mandatory=$false)] [switch]$Verbose
)

$CS_LOG_DIR   = "C:\ProgramData\CyberShield\logs"
$CS_CACHE_DIR = "C:\ProgramData\CyberShield\cache"
$NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"

if (!(Test-Path $CS_LOG_DIR))   { New-Item -ItemType Directory -Path $CS_LOG_DIR   -Force | Out-Null }
if (!(Test-Path $CS_CACHE_DIR)) { New-Item -ItemType Directory -Path $CS_CACHE_DIR -Force | Out-Null }

$LogFile = "$CS_LOG_DIR\vuln_scanner.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    if ($Verbose) { Write-Host $line }
}

# ── HMAC SIGNATURE ─────────────────────────────────────────────────────────────
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
            -Uri "$ServerURL/cybershield/api/v1/event" `
            -Method POST `
            -Body $body `
            -ContentType "application/json" `
            -Headers @{
                "X-CyberShield-Token"     = $AgentToken
                "X-CyberShield-Signature" = $signature
            } `
            -TimeoutSec 15 `
            -ErrorAction Stop
        return $response.success
    } catch {
        Write-Log "Failed to send event: $_" "ERROR"
        return $false
    }
}

# ── SEND VULNERABILITY ─────────────────────────────────────────────────────────
function Send-Vulnerability {
    param(
        [string]$CveId,
        [string]$Name,
        [string]$Component,
        [float]$CvssScore,
        [string]$CvssVector = "",
        [string]$Description = ""
    )

    $severity = switch ($true) {
        ($CvssScore -ge 9.0) { "critical" }
        ($CvssScore -ge 7.0) { "high" }
        ($CvssScore -ge 4.0) { "medium" }
        default               { "low" }
    }

    # Send as security event (vulnerability detected)
    Send-Event @{
        event_type    = "other"
        severity      = $severity
        description   = "VULNERABILITY: $CveId | $Name | Component: $Component | CVSS: $CvssScore | $Description"
        wazuh_rule_id = "CS-VULN-$($CveId -replace '[^A-Z0-9]','-')"
        mitre_tactic  = "discovery"
        raw_data      = "$CveId|$CvssScore|$CvssVector"
    } | Out-Null

    Write-Log "Vulnerability reported: $CveId ($severity, CVSS $CvssScore) - $Component"
}

# ══════════════════════════════════════════════════════════════════════════════
# 1. GET INSTALLED SOFTWARE
# ══════════════════════════════════════════════════════════════════════════════
function Get-InstalledSoftware {
    Write-Log "Scanning installed software..."

    $software = @()
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $regPaths) {
        try {
            Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and $_.DisplayVersion } |
                ForEach-Object {
                    $software += [PSCustomObject]@{
                        Name      = $_.DisplayName
                        Version   = $_.DisplayVersion
                        Publisher = $_.Publisher ?? ""
                        InstallDate = $_.InstallDate ?? ""
                    }
                }
        } catch {}
    }

    # Remove duplicates
    $software = $software | Sort-Object Name, Version -Unique
    Write-Log "Found $($software.Count) installed applications"
    return $software
}

# ══════════════════════════════════════════════════════════════════════════════
# 2. CHECK CVE DATABASE (NVD API)
# ══════════════════════════════════════════════════════════════════════════════
function Search-NvdCve {
    param([string]$Keyword, [string]$Version)

    $cacheFile = "$CS_CACHE_DIR\nvd_$($Keyword -replace '[^a-zA-Z0-9]','_').json"
    $cacheAge  = 24 # hours

    # Use cache if fresh
    if ((Test-Path $cacheFile) -and
        ((Get-Date) - (Get-Item $cacheFile).LastWriteTime).TotalHours -lt $cacheAge) {
        try {
            return Get-Content $cacheFile | ConvertFrom-Json
        } catch {}
    }

    try {
        $query = [Uri]::EscapeDataString($Keyword)
        $url = "$NVD_API_URL?keywordSearch=$query&resultsPerPage=10"

        $response = Invoke-RestMethod -Uri $url -TimeoutSec 15 -ErrorAction Stop
        $response | ConvertTo-Json -Depth 10 | Set-Content $cacheFile -Encoding UTF8

        Start-Sleep -Milliseconds 600 # NVD rate limiting: 5 req/30s without API key
        return $response

    } catch {
        Write-Log "NVD API error for '$Keyword': $_" "WARN"
        return $null
    }
}

function Get-CvssScore {
    param($CveItem)
    try {
        # Try CVSS v3.1 first, then v3.0, then v2
        $metrics = $CveItem.cve.metrics
        if ($metrics.cvssMetricV31) {
            return @{
                Score  = $metrics.cvssMetricV31[0].cvssData.baseScore
                Vector = $metrics.cvssMetricV31[0].cvssData.vectorString
            }
        }
        if ($metrics.cvssMetricV30) {
            return @{
                Score  = $metrics.cvssMetricV30[0].cvssData.baseScore
                Vector = $metrics.cvssMetricV30[0].cvssData.vectorString
            }
        }
        if ($metrics.cvssMetricV2) {
            return @{
                Score  = $metrics.cvssMetricV2[0].cvssData.baseScore
                Vector = $metrics.cvssMetricV2[0].cvssData.vectorString
            }
        }
    } catch {}
    return @{ Score = 0.0; Vector = "" }
}

# ══════════════════════════════════════════════════════════════════════════════
# 3. CHECK BROWSER VERSIONS
# ══════════════════════════════════════════════════════════════════════════════
function Check-BrowserVersions {
    Write-Log "Checking browser versions..."

    $browsers = @(
        @{
            Name    = "Google Chrome"
            Path    = "HKLM:\SOFTWARE\Google\Chrome\BLBeacon"
            ValName = "version"
            MinVersion = [version]"124.0"
        },
        @{
            Name    = "Microsoft Edge"
            Path    = "HKLM:\SOFTWARE\Microsoft\Edge"
            ValName = "version"
            MinVersion = [version]"124.0"
        },
        @{
            Name    = "Mozilla Firefox"
            Path    = "HKLM:\SOFTWARE\Mozilla\Mozilla Firefox"
            ValName = "CurrentVersion"
            MinVersion = [version]"125.0"
        }
    )

    foreach ($browser in $browsers) {
        try {
            $versionStr = (Get-ItemProperty $browser.Path -ErrorAction SilentlyContinue)."$($browser.ValName)"
            if (!$versionStr) { continue }

            # Extract version number
            $versionStr = ($versionStr -split ' ')[0]
            $version = [version]($versionStr -replace '[^0-9.]','')

            if ($version -lt $browser.MinVersion) {
                Send-Vulnerability `
                    -CveId "OUTDATED-BROWSER" `
                    -Name "$($browser.Name) outdated (v$versionStr)" `
                    -Component $browser.Name `
                    -CvssScore 7.5 `
                    -Description "Outdated browser version detected. Update recommended."
            } else {
                Write-Log "$($browser.Name) v$versionStr — OK"
            }
        } catch {
            Write-Log "Could not check $($browser.Name): $_" "WARN"
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# 4. CHECK WINDOWS UPDATE STATUS
# ══════════════════════════════════════════════════════════════════════════════
function Check-WindowsUpdates {
    Write-Log "Checking Windows Update status..."

    try {
        $updateSession   = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher  = $updateSession.CreateUpdateSearcher()
        $searchResult    = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        $pendingUpdates  = $searchResult.Updates

        $criticalCount = 0
        $importantCount = 0

        foreach ($update in $pendingUpdates) {
            # MsrcSeverity: Critical, Important, Moderate, Low
            switch ($update.MsrcSeverity) {
                "Critical"  { $criticalCount++ }
                "Important" { $importantCount++ }
            }
        }

        if ($criticalCount -gt 0) {
            Send-Vulnerability `
                -CveId "WIN-UPDATE-CRITICAL" `
                -Name "Critical Windows updates pending ($criticalCount)" `
                -Component "Windows Update" `
                -CvssScore 9.0 `
                -Description "$criticalCount critical + $importantCount important Windows updates pending installation"
        } elseif ($importantCount -gt 0) {
            Send-Vulnerability `
                -CveId "WIN-UPDATE-IMPORTANT" `
                -Name "Important Windows updates pending ($importantCount)" `
                -Component "Windows Update" `
                -CvssScore 6.5 `
                -Description "$importantCount important Windows updates pending installation"
        } elseif ($pendingUpdates.Count -gt 0) {
            Write-Log "$($pendingUpdates.Count) optional updates pending (non-critical)"
        } else {
            Write-Log "Windows is up to date"
        }

    } catch {
        Write-Log "Could not check Windows Updates: $_" "WARN"
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# 5. CHECK WEAK CONFIGURATIONS
# ══════════════════════════════════════════════════════════════════════════════
function Check-WeakConfigurations {
    Write-Log "Checking security configurations..."

    # 5.1 RDP enabled and exposed
    try {
        $rdpEnabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
            -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
        if ($rdpEnabled -eq 0) {
            $rdpConnections = Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue
            if ($rdpConnections) {
                Send-Vulnerability `
                    -CveId "CONFIG-RDP-EXPOSED" `
                    -Name "RDP (Remote Desktop) is enabled and listening" `
                    -Component "Windows RDP" `
                    -CvssScore 8.1 `
                    -Description "RDP is enabled. If exposed to internet, high risk of brute force/BlueKeep attacks."
            }
        }
    } catch {}

    # 5.2 Windows Firewall disabled
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $disabledProfiles = $profiles | Where-Object { !$_.Enabled }
        if ($disabledProfiles) {
            $names = ($disabledProfiles | Select-Object -ExpandProperty Name) -join ", "
            Send-Vulnerability `
                -CveId "CONFIG-FIREWALL-DISABLED" `
                -Name "Windows Firewall disabled on: $names" `
                -Component "Windows Firewall" `
                -CvssScore 7.5 `
                -Description "Windows Firewall is disabled on one or more network profiles."
        }
    } catch {}

    # 5.3 SMB v1 enabled (EternalBlue risk)
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($smb1 -and $smb1.State -eq "Enabled") {
            Send-Vulnerability `
                -CveId "CVE-2017-0144" `
                -Name "SMBv1 enabled (EternalBlue vulnerability)" `
                -Component "Windows SMB" `
                -CvssScore 9.8 `
                -CvssVector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" `
                -Description "SMBv1 is enabled. This is the vector used by WannaCry and NotPetya ransomware."
        }
    } catch {}

    # 5.4 AutoRun enabled (USB attack vector)
    try {
        $autoRun = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
            -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
        if ($null -eq $autoRun -or $autoRun -ne 255) {
            Send-Vulnerability `
                -CveId "CONFIG-AUTORUN-ENABLED" `
                -Name "AutoRun/AutoPlay not fully disabled" `
                -Component "Windows AutoRun" `
                -CvssScore 6.1 `
                -Description "AutoRun is not fully disabled. USB-based malware can execute automatically."
        }
    } catch {}

    # 5.5 Guest account enabled
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Send-Vulnerability `
                -CveId "CONFIG-GUEST-ENABLED" `
                -Name "Guest account is enabled" `
                -Component "Windows Accounts" `
                -CvssScore 5.0 `
                -Description "The Guest account is enabled. This may allow unauthorized access."
        }
    } catch {}

    # 5.6 Password policy
    try {
        $passPolicy = net accounts 2>$null | Out-String
        if ($passPolicy -match "Minimum password length\s+(\d+)") {
            $minLen = [int]$matches[1]
            if ($minLen -lt 8) {
                Send-Vulnerability `
                    -CveId "CONFIG-WEAK-PASSWORD-POLICY" `
                    -Name "Weak password policy (min length: $minLen)" `
                    -Component "Windows Password Policy" `
                    -CvssScore 5.5 `
                    -Description "Minimum password length is $minLen characters. Recommended minimum is 12."
            }
        }
    } catch {}

    # 5.7 Windows Defender status
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defender) {
            if (!$defender.AntivirusEnabled) {
                Send-Vulnerability `
                    -CveId "CONFIG-AV-DISABLED" `
                    -Name "Windows Defender Antivirus is disabled" `
                    -Component "Windows Defender" `
                    -CvssScore 8.0 `
                    -Description "Real-time antivirus protection is disabled on this device."
            }
            if (!$defender.RealTimeProtectionEnabled) {
                Send-Vulnerability `
                    -CveId "CONFIG-REALTIME-DISABLED" `
                    -Name "Windows Defender Real-Time Protection is disabled" `
                    -Component "Windows Defender" `
                    -CvssScore 7.5 `
                    -Description "Real-time protection is off. Malware may execute undetected."
            }
        }
    } catch {}

    Write-Log "Security configuration check complete"
}

# ══════════════════════════════════════════════════════════════════════════════
# 6. SCAN INSTALLED SOFTWARE AGAINST NVD
# ══════════════════════════════════════════════════════════════════════════════
function Scan-SoftwareVulnerabilities {
    param($Software)

    # High-risk applications to prioritize scanning
    $priorityApps = @(
        "Adobe", "Java", "Oracle", "OpenSSL", "7-Zip", "WinRAR",
        "VLC", "Zoom", "Slack", "Teams", "Python", "Node.js",
        "Git", "PuTTY", "FileZilla", "WinSCP", "TeamViewer",
        "AnyDesk", "LibreOffice", "Apache", "nginx", "MySQL",
        "PostgreSQL", "PHP", "WordPress"
    )

    $scanned = 0
    $vulnerabilitiesFound = 0

    foreach ($app in $Software) {
        # Only scan priority apps to avoid hammering NVD API
        $isPriority = $priorityApps | Where-Object { $app.Name -like "*$_*" }
        if (!$isPriority) { continue }

        Write-Log "Scanning: $($app.Name) $($app.Version)"

        $nvdResult = Search-NvdCve -Keyword $app.Name -Version $app.Version
        if (!$nvdResult -or !$nvdResult.vulnerabilities) { continue }

        foreach ($vuln in $nvdResult.vulnerabilities) {
            $cve = $vuln.cve
            $cveId = $cve.id

            # Check if CVE affects this version
            $affectsVersion = $false
            try {
                $configs = $cve.configurations
                if ($configs) {
                    foreach ($config in $configs) {
                        foreach ($node in $config.nodes) {
                            foreach ($match in $node.cpeMatch) {
                                if ($match.vulnerable -and
                                    $match.criteria -like "*$($app.Name.ToLower() -replace ' ','_')*") {
                                    $affectsVersion = $true
                                    break
                                }
                            }
                        }
                    }
                } else {
                    # No config data — report as potentially affected
                    $affectsVersion = $true
                }
            } catch {
                $affectsVersion = $true
            }

            if (!$affectsVersion) { continue }

            $cvss = Get-CvssScore -CveItem $vuln
            if ($cvss.Score -lt 4.0) { continue } # Skip low severity

            $description = ""
            try {
                $description = ($cve.descriptions | Where-Object { $_.lang -eq "en" } |
                    Select-Object -First 1).value
                if ($description.Length -gt 300) {
                    $description = $description.Substring(0, 297) + "..."
                }
            } catch {}

            Send-Vulnerability `
                -CveId $cveId `
                -Name "$cveId in $($app.Name) $($app.Version)" `
                -Component "$($app.Name) $($app.Version)" `
                -CvssScore $cvss.Score `
                -CvssVector $cvss.Vector `
                -Description $description

            $vulnerabilitiesFound++
        }

        $scanned++

        # NVD rate limit — max 5 requests per 30 seconds without API key
        if ($scanned % 4 -eq 0) {
            Write-Log "Rate limit pause (NVD API)..."
            Start-Sleep -Seconds 30
        }
    }

    Write-Log "Software scan complete: $scanned apps scanned, $vulnerabilitiesFound vulnerabilities found"
    return $vulnerabilitiesFound
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
Write-Log "═══════════════════════════════════════════════════"
Write-Log "CyberShield Vulnerability Scanner v1.0 — Starting"
Write-Log "Server: $ServerURL"
Write-Log "═══════════════════════════════════════════════════"

# Step 1: Send scan start event
Send-Event @{
    event_type  = "other"
    severity    = "info"
    description = "CyberShield vulnerability scan started on $env:COMPUTERNAME"
    wazuh_rule_id = "CS-VULN-SCAN-START"
} | Out-Null

$totalVulns = 0

# Step 2: Get installed software
$software = Get-InstalledSoftware

# Step 3: Check browser versions
Check-BrowserVersions

# Step 4: Check Windows Update status
Check-WindowsUpdates

# Step 5: Check weak configurations
Check-WeakConfigurations

# Step 6: Scan software against NVD
$totalVulns += Scan-SoftwareVulnerabilities -Software $software

# Step 7: Send scan complete event
Send-Event @{
    event_type  = "other"
    severity    = "info"
    description = "CyberShield vulnerability scan completed on $env:COMPUTERNAME — $totalVulns vulnerabilities reported"
    wazuh_rule_id = "CS-VULN-SCAN-END"
} | Out-Null

Write-Log "═══════════════════════════════════════════════════"
Write-Log "Scan complete — $totalVulns vulnerabilities found"
Write-Log "═══════════════════════════════════════════════════"
