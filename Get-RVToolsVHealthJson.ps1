<#
.SYNOPSIS
  Parse RVTools Excel -> vHealth tab -> JSON

.PARAMETER Path
  Full path to the RVTools .xlsx file.

.PARAMETER OnlyZombie
  If set, only returns rows where MessageType == 'Zombie'.

.PARAMETER Pretty
  If set, outputs indented JSON (otherwise compact).

.EXAMPLE
  .\Get-RVToolsVHealthJson.ps1 -Path 'C:\Reports\RVTools_2025-08-10.xlsx' -OnlyZombie -Pretty
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$Path,

    [switch]$OnlyZombie,
    [switch]$Pretty
)

# Ensure ImportExcel is available (no Excel app needed)
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    try {
        $null = Install-Module ImportExcel -Scope CurrentUser -Force -ErrorAction Stop
    } catch {
        Throw "Could not install ImportExcel: $($_.Exception.Message)"
    }
}
Import-Module ImportExcel -ErrorAction Stop

# Import the vHealth worksheet
try {
    $raw = Import-Excel -Path $Path -WorksheetName 'vHealth' -DataOnly -ErrorAction Stop
} catch {
    Throw "Failed to read 'vHealth' sheet from '$Path': $($_.Exception.Message)"
}

if (-not $raw -or $raw.Count -eq 0) {
    Write-Error "No rows found on the 'vHealth' worksheet."
    exit 1
}

$rows =
    $raw |
    Where-Object { $_.'Name' -and $_.'Message' } |
    ForEach-Object {
        $fullName = $_.'Name'                                # e.g. "[datastore_01] testVm01/testVm01_1-000001.vmdk"

        # Datastore inside [ ... ]
        $dsMatch   = [regex]::Match($fullName, '^\[([^\]]+)\]')
        $datastore = if ($dsMatch.Success) { $dsMatch.Groups[1].Value } else { $null }

        # Remove "[datastore] " prefix to get the path part
        $pathAfter = $fullName -replace '^\[[^\]]+\]\s*',''   # e.g. "testVm01/testVm01_1-000001.vmdk"

        # VmName = first segment before the first "/"
        $segments  = $pathAfter -split '/'
        $vmName    = if ($segments.Count -gt 0) { $segments[0].Trim() } else { $null }

        # VMDK filename = last segment after the last "/"
        $fileName  = if ($segments.Count -gt 0) { $segments[-1].Trim() } else { $null }

        [pscustomobject]@{
            Name        = $fileName
            Datastore   = $datastore
            VmName      = $vmName
            Message     = $_.'Message'
            MessageType = $_.'Message type'
            VISDKServer = $_.'VI SDK Server'
            VISDKUUID   = $_.'VI SDK UUID'
        }
    }

if ($OnlyZombie) {
    $rows = $rows | Where-Object { $_.MessageType -eq 'Zombie' }
}

# Output as JSON
if ($Pretty) {
    $rows | ConvertTo-Json -Depth 5
} else {
    $rows | ConvertTo-Json -Depth 5 -Compress
}
