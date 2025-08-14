#!/usr/bin/env pwsh
# mcp-server.ps1 - PowerShell MCP server over stdio
# pwsh -NoLogo -NonInteractive -File /Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/MCP/MCP-Server-OpenAI.ps1
# Run: pwsh -NoLogo -NonInteractive -File ./mcp-server.ps1
#
# ==== STDIO USAGE (Manual / Debug) ==========================================
# 1) Start the server (it reads JSON lines from stdin, writes JSON lines to stdout):
#      pwsh -NoLogo -NonInteractive -File /Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/MCP/MCP-Server-OpenAI.ps1
#
# 2) In another shell, you can pipe JSON into the process. Example with a heredoc:
#      pwsh -NoLogo -NonInteractive -File /Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/MCP/MCP-Server-OpenAI.ps1 <<'EOF'
#      {"method":"initialize","id":1,"jsonrpc":"2.0"}
#      {"method":"tools/list","id":2,"jsonrpc":"2.0"}
#      EOF
#
#    (Above exits after EOF; for interactive testing open a terminal multiplexer
#     or use a small wrapper script that keeps stdin open.)
#
# 3) Example tool call (replace VMName etc. as needed):
#      {"method":"tools/call","id":3,"jsonrpc":"2.0","params":{"name":"Get-vCenter-Host-Health","arguments":{}}}
#      {"method":"tools/call","id":4,"jsonrpc":"2.0","params":{"name":"Send-Email","arguments":{"ToEmail":"dale.hassinger@outlook.com","Subject":"Test","Body":"Hi"}}}
#
# 4) Using echo (single command):
#      echo '{"method":"initialize","id":10,"jsonrpc":"2.0"}' | pwsh -NoLogo -NonInteractive -File /Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/MCP/MCP-Server-OpenAI.ps1
#
# 5) Programmatic client outline (pseudo):
#      - spawn process: pwsh -NoLogo -NonInteractive -File MCP-Server-OpenAI.ps1
#      - write one JSON object per line to stdin
#      - read one JSON line per response from stdout
#
# 6) The server does NOT open a TCP port; all communication is line-delimited JSON over stdio.
# 
# cli Prompts tested by Hackathon Team
<#

pwsh -NoLogo -NonInteractive -File /Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/MCP/MCP-Server-OpenAI.ps1 <<'EOF'
{"method":"tools/call","id":3,"jsonrpc":"2.0","params":{"name":"Get-vCenter-Host-Health","arguments":{}}}
EOF


pwsh -NoLogo -NonInteractive -File /Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/MCP/MCP-Server-OpenAI.ps1 <<'EOF'
{"method":"tools/call","id":4,"jsonrpc":"2.0","params":{"name":"Send-Email","arguments":{"ToEmail":"dale.hassinger@outlook.com","Subject":"Test","Body":"Hi"}}}
EOF

pwsh -NoLogo -NonInteractive -File /Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/MCP/MCP-Server-OpenAI.ps1 <<'EOF'
{"method":"tools/call","id":3,"jsonrpc":"2.0","params":{"name":"Get-Network-Switch-Stats","arguments":{}}} 
EOF

echo '{"method":"tools/call","id":3,"jsonrpc":"2.0","params":{"name":"Get-Network-Switch-Stats","arguments":{}}}' | pwsh -NoLogo -NonInteractive -File /Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/MCP/MCP-Server-OpenAI.ps1

echo '{"method":"tools/call","id":4,"jsonrpc":"2.0","params":{"name":"Send-Email","arguments":{"ToEmail":"dale.hassinger@outlook.com","Subject":"MCP Email","Body":"Hi, welcome to the Hackathon!"}}}' | pwsh -NoLogo -NonInteractive -File /Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/MCP/MCP-Server-OpenAI.ps1

#>
#
# ============================================================================

using namespace System.Text
using namespace System.IO
using namespace System.Collections.Generic


# Load YAML configuration file
$cfgFile = "/Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/Home-Lab-Config.yaml"
if (-not (Test-Path $cfgFile)) {
    Write-Host "Configuration file '$cfgFile' not found." -ForegroundColor Red
    exit 1
}
try {
    $cfg = Get-Content -Path $cfgFile -Raw | ConvertFrom-Yaml
    if (-not $cfg.vCenter -or -not $cfg.vCenter.server -or -not $cfg.vCenter.username -or -not $cfg.vCenter.password) {
        Write-Host "Invalid YAML configuration: Missing vCenter server, username, or password." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Failed to parse YAML configuration: $_" -ForegroundColor Red
    exit 1
}






# --------------------------
# CONFIG: Which functions to expose?
#   Option A: Import a module and expose its exported functions
#   Option B: Add functions directly in this file
# --------------------------

# Example functions (replace with your own or Import-Module)
function Get-HostUptime {
    <#
    .SYNOPSIS
      Returns host uptime in seconds
    #>
    [CmdletBinding()]
    param()
    $ticks = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
    [pscustomobject]@{
        UptimeSeconds = [int]$ticks.TotalSeconds
        BootTime      = (gcim Win32_OperatingSystem).LastBootUpTime
    } | ConvertTo-Json -Depth 5
} # End Function


function Send-Email {
    <#
    .SYNOPSIS
      Sends an HTML email via Gmail SMTP and returns a JSON status.
    .DESCRIPTION
      Creates and sends an HTML email using the specified recipient, subject, and body.
      Returns a compact JSON string indicating Success or Error.
    .PARAMETER ToEmail
      Recipient email address or a list separated by comma/semicolon (e.g. "a@b.com;c@d.com").
    .PARAMETER Subject
      Subject line for the email.
    .PARAMETER Body
      HTML body content for the email. The message is sent with IsBodyHtml = $true.
    .OUTPUTS
      System.String (JSON)
    .EXAMPLE
      Send-Email -ToEmail "user@example.com" -Subject "Hello" -Body "<p>Hi there</p>"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ToEmail,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Subject,
        [Parameter()]
        [string]$Body
    )
    # Email details
    $fromEmail = "dale.hassinger@gmail.com"

    # Default HTML body if none provided
    if (-not $PSBoundParameters.ContainsKey('Body') -or [string]::IsNullOrWhiteSpace($Body)) {
        $Body = '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>vCROCS Automation</title>
        <style>
            body { background-color:#ffffff; color:#000000; font-family:Arial,sans-serif; font-size:14px; margin:0; padding:20px; }
        </style></head><body>
        <p>VCF Operations Diagnostic Data attached to this email as an Excel File.</p>
        <p>Created by: vCROCS Automation</p>
        </body></html>'
    }

    # Gmail SMTP server details
    $smtpServer  = "smtp.gmail.com"
    $smtpPort    = 587
    $appPassword = $cfg.gmail.appPassword

    # Create the email message
    $emailMessage = New-Object system.net.mail.mailmessage
    $emailMessage.From = $fromEmail

    # Normalize and add recipients (support comma/semicolon, trim blanks)
    $recipients = $ToEmail -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if (-not $recipients -or $recipients.Count -eq 0) {
        [PSCustomObject]@{ Status="Error"; Message="ToEmail is empty after normalization." } | ConvertTo-Json -Compress
        return
    }
    foreach ($addr in $recipients) { $emailMessage.To.Add($addr) }

    $emailMessage.Subject = $Subject
    $emailMessage.Body = $Body
    $emailMessage.IsBodyHtml = $true

    # Configure the SMTP client
    $smtpClient = New-Object system.net.mail.smtpclient($smtpServer, $smtpPort)
    $smtpClient.EnableSsl = $true
    $smtpClient.Credentials = New-Object System.Net.NetworkCredential($fromEmail, $appPassword)

    # Send the email
    try {
        $smtpClient.Send($emailMessage)
        [PSCustomObject]@{
            Status  = "Success"
            Message = "Email sent successfully."
        } | ConvertTo-Json -Compress
    } catch {
        [PSCustomObject]@{
            Status  = "Error"
            Message = "Failed to send email: $($_.Exception.Message)"
        } | ConvertTo-Json -Compress
    } finally {
        $smtpClient.Dispose()
    }
} # End function



function Get-vCenter-Host-Tiered-Memory-Usage {
    <#
    .SYNOPSIS
      Collect tiered memory usage for all VMs across ESXi hosts and return JSON.
    .DESCRIPTION
      Connects to vCenter, enumerates ESXi hosts, then SSHes to each host to fetch:
        - VM process list (to map VMX Cartel IDs to VM display names)
        - memstats vmtier-stats (tiered memory usage per VM in MB)
      Produces a JSON array of objects with Host, Name, MemSizeMB, ActiveMB, Tier0-RAM, Tier1-NVMe.
      vCLS system VMs are excluded.
    .REQUIREMENTS
      - VMware PowerCLI
      - sshpass available in PATH on the machine running this function
    .OUTPUTS
      System.String (JSON)
    .EXAMPLE
      Get-vCenter-Host-Tiered-Memory-Usage
    #>
    [CmdletBinding()]
    param()

    # Resolve vCenter connection info (prefer YAML config if present)
    $vcServer   = if ($cfg.vCenter.server)   { $cfg.vCenter.server }   else { "vcsa8x.vcrocs.local" }
    $vcUsername = if ($cfg.vCenter.username) { $cfg.vCenter.username } else { "administrator@vcrocs.local" }
    $vcPassword = if ($cfg.vCenter.password) { $cfg.vCenter.password } else { "VMware1!" }

    try {
        # Connect to vCenter
        Connect-VIServer -Server $vcServer -User $vcUsername -Password $vcPassword -Protocol https -Force -ErrorAction Stop | Out-Null

        # Validate sshpass availability (required for ESXi SSH)
        if (-not (Get-Command sshpass -ErrorAction SilentlyContinue)) {
            throw "sshpass is not installed or not in PATH. Install sshpass and try again."
        }

        # Enumerate ESXi hosts
        $esxiHosts = Get-VMHost -ErrorAction Stop

        # Aggregate results for all hosts
        $combinedResults = @()

        foreach ($esxiHost in $esxiHosts) {
            $server   = $esxiHost.Name
            $username = "root"        # TODO: Prefer secure storage or YAML config
            $password = "VMware1!"    # TODO: Prefer secure storage or YAML config

            Write-Verbose "Querying host $server for VM list and tiered memory stats"

            # 1) Build VMX CartelID -> DisplayName map from esxcli (CSV)
            $vmCommand = "esxcli --formatter csv vm process list"
            $args_vm = @(
                "-p", $password, "ssh",
                "-o","ConnectTimeout=10",
                "-o","PreferredAuthentications=password",
                "-o","PubkeyAuthentication=no",
                "-o","StrictHostKeyChecking=no",
                "-o","LogLevel=QUIET",
                "$username@$server",
                $vmCommand
            )
            $vmCsv = & sshpass @args_vm 2>$null
            $vmNameMap = @{}
            if ($vmCsv) {
                try {
                    $vmRows = $vmCsv | ConvertFrom-Csv
                    foreach ($row in $vmRows) {
                        # Try common id/display column names with fallbacks
                        $id = $row.VMXCartelID; if (-not $id) { $id = $row.CartelID }
                        if (-not $id) { $id = $row.WorldID }
                        $name = $row.DisplayName; if (-not $name) { $name = $row.Name }
                        if ($id -and $name) { $vmNameMap[$id] = $name }
                    }
                } catch {
                    Write-Verbose "Failed to parse VM CSV for $($server): $($_.Exception.Message)"
                }
            }

            # 2) Query tiered memory stats
            $memCommand = 'memstats -r vmtier-stats -u mb -s name:memSize:active:tier0Consumed:tier1Consumed'
            $args_mem = @(
                "-p", $password, "ssh",
                "-o","ConnectTimeout=10",
                "-o","PreferredAuthentications=password",
                "-o","PubkeyAuthentication=no",
                "-o","StrictHostKeyChecking=no",
                "-o","LogLevel=QUIET",
                "$username@$server",
                $memCommand
            )
            $memOutput = & sshpass @args_mem 2>$null
            if (-not $memOutput) { continue }

            # Normalize and filter lines
            $lines = $memOutput -split "`n" |
                     ForEach-Object { $_.Trim() } |
                     Where-Object { $_ -and $_ -notmatch '^-{2,}|Total|Start|No\.|VIRTUAL|Unit|Selected' }

            # Regex shape: "vm.<cartelId>  <memSize>  <active>  <tier0>  <tier1>"
            $pattern = '^(?<name>\S+)\s+(?<memSize>\d+)\s+(?<active>\d+)\s+(?<tier0Consumed>\d+)\s+(?<tier1Consumed>\d+)$'

            foreach ($line in $lines) {
                if ($line -match $pattern) {
                    $nameKey = ($matches['name'] -replace '^vm\.', '')
                    $display = if ($vmNameMap.ContainsKey($nameKey)) { $vmNameMap[$nameKey] } else { $nameKey }

                    # Exclude system VMs
                    if ($display -like 'vCLS-*') { continue }

                    $combinedResults += [pscustomobject]@{
                        Host         = $server
                        Name         = $display
                        MemSizeMB    = [int]$matches['memSize']
                        ActiveMB     = [int]$matches['active']
                        'Tier0-RAM'  = [int]$matches['tier0Consumed']
                        'Tier1-NVMe' = [int]$matches['tier1Consumed']
                    }
                }
            }
        } # end foreach host

        # Emit JSON
        $combinedResults | ConvertTo-Json -Depth 4
    }
    catch {
        # Return compact JSON error
        [pscustomobject]@{
            Status  = 'Error'
            Message = $_.Exception.Message
        } | ConvertTo-Json -Compress
    }
    finally {
        # Ensure VI disconnect
        try { Disconnect-VIServer -Server * -Confirm:$false | Out-Null } catch {}
    }
} # End Function

function Get-vCenter-Host-Health {
    <#
    .SYNOPSIS
      Return the latest vROps 'badge|health' metric per vCenter ESXi host as JSON.
    .DESCRIPTION
      Connects to VCF Operations (vROps) at 192.168.6.99 using admin credentials, enumerates HostSystem
      resources, fetches the most recent 'badge|health' sample within the last 24 hours for each host,
      and emits an array of objects with Resource, Time, and Value as a JSON string.
    .OUTPUTS
      System.String (JSON)
    .EXAMPLE
      Get-Host-Health
      [
        { "Resource": "esxi01.lab.local", "Time": "2025-08-10T12:34:56Z", "Value": 100 }
      ]
    #>
    [CmdletBinding()]
    param()

    # Connect to VCF Operations (vROps)
    Connect-OMServer -Server $cfg.OPS.opsIP -User $cfg.OPS.opsUsername -Password $cfg.OPS.opsPassword -Force

    # Get HostSystem resources as a unique, sorted list of names
    $hostNames = Get-OMResource |
        Where-Object { $_.ResourceKind -like "*HostSystem*" } |
        Select-Object -ExpandProperty Name |
        Sort-Object -Unique

    # Collect host health into an array
    $results = @()

    foreach ($name in $hostNames) {
        $sample = Get-OMStat -Resource $name -Key 'badge|health' -From (Get-Date).AddDays(-1) |
                  Sort-Object Time -Descending |
                  Select-Object -First 1

        if ($null -ne $sample) {
            $results += [pscustomobject]@{
                Resource = $name
                Time     = $sample.Time
                Value    = $sample.Value
            }
        } else {
            $results += [pscustomobject]@{
                Resource = $name
                Time     = $null
                Value    = $null
            }
        }
    } # End foreach

    # Emit JSON
    $results | ConvertTo-Json -Depth 3

    Disconnect-OMServer -Confirm:$false

} # End Function

function Get-All-vCenter-VMs {
    <#
    .SYNOPSIS
      Return vCenter VMs (all by default) and their properties as JSON
    .PARAMETER Name
      Optional name or pattern to filter VMs
    #>

    # Suppress banners/warnings/verbose/progress for this function scope
    $prefBackup = @{
        Warning      = $WarningPreference
        Verbose      = $VerbosePreference
        Information  = $InformationPreference
        Progress     = $ProgressPreference
    }
    $WarningPreference     = 'SilentlyContinue'
    $VerbosePreference     = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference    = 'SilentlyContinue'

    try {
        if (-not (Get-Module -ListAvailable -Name VMware.PowerCLI)) {
            throw "VMware.PowerCLI module not found. Install with: Install-Module VMware.PowerCLI -Scope CurrentUser"
        }
        Import-Module VMware.PowerCLI -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null

        # Avoid prompts/cert warnings
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
        Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false | Out-Null

        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop

        # Get VMs excluding vCLS system VMs
        $vms = Get-VM -ErrorAction Stop | Where-Object { $_.Name -notlike 'vCLS-*' }
        $return = $vms | Select-Object Name, PowerState, NumCPU, CoresPerSocket, MemoryGB, UsedSpaceGB, ProvisionedSpaceGB, CreateDate | ConvertTo-Json -Depth 5

        # Return all VM properties, excluding problematic ones to avoid JSON errors
        $return
        
        #Get-Stat -Entity VAO -MaxSamples 1 

    }
    catch {
        @{ error = $_.Exception.Message } | ConvertTo-Json -Depth 5
    }
    finally {
        try { if ($si) { Disconnect-VIServer -Server $si -Confirm:$false | Out-Null } } catch {}
        # Restore preferences
        $WarningPreference     = $prefBackup.Warning
        $VerbosePreference     = $prefBackup.Verbose
        $InformationPreference = $prefBackup.Information
        $ProgressPreference    = $prefBackup.Progress
    }
} # End Function

function Get-vCenter-VM-Stats {
    <#
    .SYNOPSIS
      Return vCenter VMs (all by default) and their properties as JSON
    .PARAMETER Name
      Optional name or pattern to filter VMs
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName
    )

    # Suppress banners/warnings/verbose/progress for this function scope
    $prefBackup = @{
        Warning      = $WarningPreference
        Verbose      = $VerbosePreference
        Information  = $InformationPreference
        Progress     = $ProgressPreference
    }
    $WarningPreference     = 'SilentlyContinue'
    $VerbosePreference     = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    $ProgressPreference    = 'SilentlyContinue'

    try {
        if (-not (Get-Module -ListAvailable -Name VMware.PowerCLI)) {
            throw "VMware.PowerCLI module not found. Install with: Install-Module VMware.PowerCLI -Scope CurrentUser"
        }
        Import-Module VMware.PowerCLI -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null

        # Avoid prompts/cert warnings
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
        Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false | Out-Null

        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop

        $vm = Get-VM -Name $VMName -ErrorAction Stop

        Get-Stat -Entity $vm `
                -Stat cpu.usage.average, cpu.usagemhz.average, mem.usage.average, disk.usage.average, net.usage.average, sys.uptime.latest `
                -Start (Get-Date).AddHours(-1) -MaxSamples 1 |
        Select-Object @{Name='VMName';Expression={$vm.Name}},
                    MetricId, Timestamp, Value, Unit, Instance |
        ConvertTo-Json -Depth 3

    }
    catch {
        @{ error = $_.Exception.Message } | ConvertTo-Json -Depth 5
    }
    finally {
        try { if ($si) { Disconnect-VIServer -Server $si -Confirm:$false | Out-Null } } catch {}
        # Restore preferences
        $WarningPreference     = $prefBackup.Warning
        $VerbosePreference     = $prefBackup.Verbose
        $InformationPreference = $prefBackup.Information
        $ProgressPreference    = $prefBackup.Progress
    }
} # End Function



function Get-Network-Switch-Stats {
    <#
    .SYNOPSIS
    Collects system utilization and fan status from a TRENDnet TEG-7124WS and returns JSON.
    .REQUIREMENTS
    Install-Module Posh-SSH
    #>

    # --- Fixed connection details ---
    $Ip       = $cfg.Switch.SwitchIP
    $User     = $cfg.Switch.SwitchUser
    $Password = $cfg.Switch.SwitchPW

    # --- Prep credentials ---
    $sec  = ConvertTo-SecureString $Password -AsPlainText -Force
    $cred = [pscredential]::new($User, $sec)

    # --- Ensure Posh-SSH is available ---
    if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
        throw "Posh-SSH module not found. Install it with: Install-Module Posh-SSH"
    }

    Import-Module Posh-SSH -ErrorAction Stop

    # --- Helper: read until timeout ---
    function Invoke-TrendnetCommand {
        param(
            [Parameter()] [string]$Command = '',
            [Parameter(Mandatory)] [object]$Stream,
            [int]$TimeoutSec = 5
        )

        Start-Sleep -Milliseconds 300
        $null = $Stream.Read()

        if ($Command) {
            $Stream.WriteLine($Command)
        }

        $buffer = ''
        $deadline = (Get-Date).AddSeconds($TimeoutSec)

        do {
            Start-Sleep -Milliseconds 200
            $chunk = $Stream.Read()
            if ($chunk) { $buffer += $chunk }
        } while ((Get-Date) -lt $deadline)

        # Clean up
        $buffer = $buffer -replace "`r",""
        $buffer = $buffer -replace '\x1B\[[0-9;]*[A-Za-z]', ''  # strip ANSI escape codes
        $lines  = $buffer -split "`n" | ForEach-Object { $_.Trim() }

        # Remove echoed command and blank lines
        $lines = $lines | Where-Object { $_ -and ($_ -ne $Command) }

        ($lines -join "`n").Trim()
    }

    # --- Parse system utilization ---
    function Parse-Utilization {
        param([Parameter(Mandatory)][string]$Text)
        $lines = $Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }

        $cpuData = @{}
        $cpuStart = ($lines | Select-String -Pattern '^CPU Utilization:').LineNumber
        if ($cpuStart) {
            for ($i = $cpuStart; $i -lt $lines.Count; $i++) {
                $line = $lines[$i]
                if ($i -gt $cpuStart -and ($line -match '^Memory Utilization:' -or $line -eq '')) { break }
                if ($line -match '^(?<k>\S+)\s*:\s*(?<v>[\d\.]+)') {
                    $cpuData[$matches.k] = [double]$matches.v
                }
            }
        }

        $memData = @{}
        $memStart = ($lines | Select-String -Pattern '^Memory Utilization:').LineNumber
        if ($memStart) {
            for ($i = $memStart; $i -lt $lines.Count; $i++) {
                $line = $lines[$i]
                if ($i -gt $memStart -and $line -eq '') { break }
                if ($line -match '^(?<k>\S+)\s*:\s*(?<n>\d+)\s*(?<unit>MB|KB|GB)?$') {
                    $n = [int]$matches.n
                    switch -Regex ($matches.unit) {
                        'GB' { $n *= 1024 }
                        'KB' { $n = [int][math]::Round($n / 1024.0) }
                    }
                    $memData[$matches.k] = $n
                }
            }
        }

        [pscustomobject]@{
            CPU    = $cpuData
            Memory = $memData
        }
    }

    # --- Parse fan status ---
    function Parse-FanStatus {
        param([Parameter(Mandatory)][string]$Text)
        $status = 'UNKNOWN'
        foreach ($line in ($Text -split "`n")) {
            if ($line -match '^System Fan Status:\s*(?<s>.+?)\s*$') {
                $status = $matches.s.Trim()
                break
            }
        }
        $status
    }

    # --- Parse interface status ---
    function Parse-InterfaceStatus {
        param([Parameter(Mandatory)][string]$Text)
        $lines = $Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        $interfaces = @()
        
        $headerFound = $false
        foreach ($line in $lines) {
            if ($line -match '^Port\s+Status\s+Duplex\s+Speed\s+Negotiation\s+Capability') {
                $headerFound = $true
                continue
            }
            if ($line -match '^-+\s+-+\s+-+\s+-+\s+-+\s+-+') {
                continue
            }
            if ($headerFound -and $line -match '^\S+' -and $line -notmatch '--More--') {
                # Split and clean up the line
                $cleanParts = ($line -replace '\s+', ' ') -split ' '
                
                # Skip invalid entries and only include Gi0 ports
                if ($cleanParts[0] -eq '--More--' -or $cleanParts[0] -match '^-+$' -or $cleanParts[0] -notmatch '^Gi0') {
                    continue
                }
                
                $interface = [pscustomobject]@{
                    Port = $cleanParts[0]
                    Status = if ($cleanParts[1] -eq 'not') { 'not connected' } else { $cleanParts[1] }
                    Duplex = if ($cleanParts[1] -eq 'not') { $cleanParts[3] } else { $cleanParts[2] }
                    Speed = if ($cleanParts[1] -eq 'not') { 
                        if ($cleanParts[4] -eq '-') { '-' } else { $cleanParts[4] + ' ' + $cleanParts[5] }
                    } else { 
                        if ($cleanParts[3] -eq '-') { '-' } else { $cleanParts[3] + ' ' + $cleanParts[4] }
                    }
                    Negotiation = if ($cleanParts[1] -eq 'not') { 
                        if ($cleanParts.Count -gt 5) { $cleanParts[5] } else { '' }
                    } else { 
                        if ($cleanParts.Count -gt 4) { $cleanParts[4] } else { '' }
                    }
                    Capability = if ($cleanParts[1] -eq 'not') { 
                        if ($cleanParts.Count -gt 6) { ($cleanParts[6..($cleanParts.Count-1)] -join ' ') } else { '' }
                    } else { 
                        if ($cleanParts.Count -gt 5) { ($cleanParts[5..($cleanParts.Count-1)] -join ' ') } else { '' }
                    }
                }
                $interfaces += $interface
            }
        }
        
        return $interfaces
    }

    # --- Main ---
    $session = $null
    try {
        $session = New-SSHSession -ComputerName $Ip -Credential $cred -AcceptKey -ErrorAction Stop
        $stream  = New-SSHShellStream -SessionId $session.SessionId -TerminalName 'vt100'

        # Force prompt
        $null = Invoke-TrendnetCommand -Stream $stream -Command ''

        # Run commands
        $utilRaw = Invoke-TrendnetCommand -Stream $stream -Command 'show system utilization'
        $fanRaw  = Invoke-TrendnetCommand -Stream $stream -Command 'show system fan status'
        $intRaw  = Invoke-TrendnetCommand -Stream $stream -Command 'show interfaces status'

        # Debug
        # Write-Host "DEBUG Utilization:`n$utilRaw"
        # Write-Host "DEBUG Fan:`n$fanRaw"
        # Write-Host "DEBUG Interfaces:`n$intRaw"

        # Parse
        if (-not $utilRaw) { throw "No output from 'show system utilization'" }
        $util = Parse-Utilization -Text $utilRaw
        $fan  = Parse-FanStatus -Text $fanRaw
        $interfaces = Parse-InterfaceStatus -Text $intRaw

        # Output JSON
        $result = [pscustomobject]@{
            Device     = 'TEG-7124WS'
            Target     = $Ip
            CPU        = $util.CPU
            Memory     = $util.Memory
            Fan        = $fan
            Interfaces = $interfaces
        }

        #        Fetched    = (Get-Date).ToString('s')

        $result | ConvertTo-Json -Depth 5
    }
    finally {
        if ($session) { Remove-SSHSession -SessionId $session.SessionId | Out-Null }
    }    
} # End Function

# If you prefer module-based discovery:
# Import-Module ./YourModule.psm1 -Force

# --------------------------
# Utility: JSON-RPC I/O
# --------------------------
$stdin  = [Console]::OpenStandardInput()
$stdout = [Console]::OpenStandardOutput()
# Use UTF-8 without BOM to avoid sending U+FEFF
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$reader = New-Object IO.StreamReader($stdin, $utf8NoBom, $false, 4096, $true)
$writer = New-Object IO.StreamWriter($stdout, $utf8NoBom, 4096, $true)
$writer.AutoFlush = $true
$stderr = [Console]::Error

function Write-JsonRpc {
    param(
        [Parameter(Mandatory)] [hashtable]$Object
    )
    try {
        $json = ($Object | ConvertTo-Json -Depth 10 -Compress)
        $writer.WriteLine($json)
    } catch {
        $stderr.WriteLine("Write-JsonRpc error: $_")
    }
}

function Read-JsonLine {
    try {
        $line = $reader.ReadLine()
        if ($null -eq $line) { return $null }
        if ($line.Trim().Length -eq 0) { return @{} }
        return ($line | ConvertFrom-Json -Depth 20)
    } catch {
        $stderr.WriteLine("Read-JsonLine parse error: $_")
        return $null
    }
}

# --------------------------
# Discover tools (functions)
# --------------------------
function Get-ToolSchemaFromParam {
    param([Parameter(Mandatory)][System.Management.Automation.ParameterMetadata]$Param)
    $typeName = $Param.ParameterType.FullName
    switch ($typeName) {
        "System.String"     { return @{ type = "string" } }
        "System.Int32"      { return @{ type = "integer" } }
        "System.Int64"      { return @{ type = "integer" } }
        "System.Double"     { return @{ type = "number" } }
        "System.Boolean"    { return @{ type = "boolean" } }
        "System.Collections.Hashtable" { return @{ type = "object" } }
        default             { return @{ type = "string" } } # fallback
    }
}

function Get-ToolList {
    param(
        [string[]]$FunctionNames
    )
    $tools = @()
    foreach ($fn in $FunctionNames) {
        $cmd = Get-Command $fn -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        $params = @{}
        $required = @()
        foreach ($kvp in $cmd.Parameters.GetEnumerator()) {
            $p = $kvp.Value
            # Filter out common/engine parameters so schemas stay concise
            if ($p.Name -in @(
                'Verbose','Debug','ErrorAction','WarningAction','InformationAction','OutVariable','OutBuffer','PipelineVariable',
                'InformationVariable','WarningVariable','ErrorVariable','ProgressAction','WhatIf','Confirm'
            )) { continue }
            $schema = Get-ToolSchemaFromParam -Param $p
            $params[$p.Name] = $schema
            if ($p.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory }) {
                $required += $p.Name
            }
        }
        $schemaObj = @{
            type       = "object"
            properties = $params
        }
        if ($required.Count -gt 0) { $schemaObj.required = $required }

        $help = (Get-Help $fn -ErrorAction SilentlyContinue)
        $desc = if ($help.Synopsis) { $help.Synopsis } else { "PowerShell function: $fn" }

        $tools += @{
            name        = $fn
            description = $desc
            inputSchema = $schemaObj
        }
    }
    return ,$tools
}

# Pick which functions to expose
$FunctionsToExpose = @(
    'Get-HostUptime',
    'Get-All-vCenter-VMs',
    'Get-vCenter-VM-Stats',
    'Get-Network-Switch-Stats',
    'Send-Email',
    'Get-vCenter-Host-Health',
    'Get-vCenter-Host-Tiered-Memory-Usage'
    # Add your PowerCLI / ops functions here, e.g. 'Get-VM', 'Get-ClusterStatus', etc.
)

$ToolIndex = @{}
(Get-ToolList -FunctionNames $FunctionsToExpose) | ForEach-Object {
    $ToolIndex[$_.name] = $_
}

# --------------------------
# JSON-RPC Handlers
# --------------------------
function Send-Result {
    param($id, $result)
    Write-JsonRpc @{
        jsonrpc = "2.0"
        id      = $id
        result  = $result
    }
}

function Send-Error {
    param($id, [int]$code, [string]$message, $data=$null)
    $err = @{
        code    = $code
        message = $message
    }
    if ($null -ne $data) { $err.data = $data }
    Write-JsonRpc @{
        jsonrpc = "2.0"
        id      = $id
        error   = $err
    }
}

# Utility: Convert PSCustomObject (from ConvertFrom-Json) into Hashtable for splatting
function ConvertTo-HashtableDeep {
    param([Parameter()]$InputObject)
    if ($null -eq $InputObject) { return @{} }
    if ($InputObject -is [System.Collections.IDictionary]) {
        return @{} + $InputObject
    }
    if ($InputObject -is [psobject]) {
        $h = @{}
        foreach ($p in $InputObject.PSObject.Properties) {
            $h[$p.Name] = ConvertTo-HashtableDeep -InputObject $p.Value
        }
        return $h
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $list = @()
        foreach ($item in $InputObject) {
            $list += ,(ConvertTo-HashtableDeep -InputObject $item)
        }
        return ,$list
    }
    return $InputObject
}

# Main loop
$stderr.WriteLine("PowerShell MCP Server starting...")
while ($true) {
    try {
        $msg = Read-JsonLine
        if ($null -eq $msg) { 
            $stderr.WriteLine("Exiting main loop - null message")
            break 
        } # EOF
        if (-not $msg.method) { 
            $stderr.WriteLine("Skipping message without method")
            continue 
        }

        $id     = $msg.id
        $method = $msg.method
        $params = $msg.params

        $stderr.WriteLine("Processing method: $method with id: $id")

        switch ($method) {

            'initialize' {
                # Respond with MCP capabilities
                $result = @{
                    protocolVersion = "2024-11-05"  # nominal MCP version label; adjust if needed
                    serverInfo      = @{
                        name    = "powershell-mcp-server"
                        version = "0.1.0"
                    }
                    capabilities = @{
                        tools = @{}
                    }
                }
                Send-Result $id $result
            }

            'notifications/initialized' {
                # Notification (no id) — do not send a response
                continue
            }

            'tools/list' {
                $result = @{
                    tools = @($ToolIndex.Values)
                }
                Send-Result $id $result
            }

            'resources/list' {
                # Minimal implementation: no resources
                Send-Result $id @{ resources = @() }
            }

            'prompts/list' {
                # Minimal implementation: no prompts
                Send-Result $id @{ prompts = @() }
            }

            'tools/call' {
                try {
                    $name = $params.name
                    $args = $params.arguments

                    if (-not $ToolIndex.ContainsKey($name)) {
                        Send-Error $id -32601 "Unknown tool: $name"
                        continue
                    }

                    # Build splat: handle Hashtable, IDictionary, and PSCustomObject from JSON
                    $splat = @{}
                    if ($args -is [hashtable]) {
                        $splat = $args
                    } elseif ($args -is [System.Collections.IDictionary]) {
                        $splat = @{} + $args
                    } elseif ($args -ne $null) {
                        $splat = ConvertTo-HashtableDeep -InputObject $args
                    }

                    # Temporarily silence noisy preferences during tool run
                    $prefBackup = @{
                        Warning      = $WarningPreference
                        Verbose      = $VerbosePreference
                        Information  = $InformationPreference
                        Progress     = $ProgressPreference
                    }
                    $WarningPreference     = 'SilentlyContinue'
                    $VerbosePreference     = 'SilentlyContinue'
                    $InformationPreference = 'SilentlyContinue'
                    $ProgressPreference    = 'SilentlyContinue'

                    $output = & $name @splat *>&1

                    # Restore preferences
                    $WarningPreference     = $prefBackup.Warning
                    $VerbosePreference     = $prefBackup.Verbose
                    $InformationPreference = $prefBackup.Information
                    $ProgressPreference    = $prefBackup.Progress

                    # Normalize and strip ANSI color codes
                    $outText = if ($output -is [string]) { $output } else { ($output | Out-String) }
                    $outText = [regex]::Replace($outText, "`e\[[\d;]*[A-Za-z]", '')

                    $result = @{
                        content = @(
                            @{
                                type = "text"
                                text = $outText
                            }
                        )
                        isError = $false
                    }
                    Send-Result $id $result
                } catch {
                    $result = @{
                        content = @(
                            @{
                                type = "text"
                                text = $_ | Out-String
                            }
                        )
                        isError = $true
                    }
                    Send-Result $id $result
                }
            }

            default {
                # Only reply with an error for real requests (id present), ignore notifications
                if ($null -ne $id) {
                    Send-Error $id -32601 "Method not implemented: $method"
                }
            }
        }
    } catch {
        $stderr.WriteLine("Error in main loop: $_")
        if ($id) {
            Send-Error $id -32603 "Internal error: $_"
        }
    }
}

$stderr.WriteLine("PowerShell MCP Server stopped")

# Claude Setup
<#
{
  "mcpServers": {
    "powershell-mcp": {
      "command": "pwsh",
      "args": [
        "-NoLogo",
        "-NonInteractive",
        "-File",
        "/absolute/path/to/mcp-server.ps1"
      ],
      "env": {}
    }
  }
}
#>