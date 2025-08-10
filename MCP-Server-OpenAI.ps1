#!/usr/bin/env pwsh
# mcp-server.ps1 - PowerShell MCP server over stdio
# Run: pwsh -NoLogo -NonInteractive -File ./mcp-server.ps1

using namespace System.Text
using namespace System.IO
using namespace System.Collections.Generic

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

function Get-All-VMs {
    <#
    .SYNOPSIS
      Return vCenter VMs (all by default) and their properties as JSON
    .PARAMETER Name
      Optional name or pattern to filter VMs
    #>

    $server = '192.168.6.101'
    $username = 'root'
    $password = 'VMware1!'

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

        $secure = ConvertTo-SecureString $password -AsPlainText -Force
        $cred = [pscredential]::new($username, $secure)

        $si = Connect-VIServer -Server $server -Credential $cred -ErrorAction Stop

        $vms = Get-VM  -ErrorAction Stop
        $return = $vms | Select-Object Name, PowerState, NumCPU, CoresPerSocket, MemoryGB | ConvertTo-Json -Depth 5

        # Return all VM properties, excluding problematic ones to avoid JSON errors
        $return
        
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
    'Get-All-VMs'
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

                    # Invoke function with splatting, capturing ALL streams to prevent stdout leakage
                    $splat = @{}
                    if ($args -is [hashtable]) {
                        $splat = $args
                    } elseif ($args -is [System.Collections.IDictionary]) {
                        $splat = @{} + $args
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