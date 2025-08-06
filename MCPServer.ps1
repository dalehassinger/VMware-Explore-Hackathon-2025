# Requires -Module PSMCP
Set-LogFile "/Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/MCP/mcp_server.log"

<#
.SYNOPSIS
    PowerShell MCP server for vCenter operations, including VM memory information.

.DESCRIPTION
    Provides MCP tools for basic arithmetic and VMware vCenter VM information retrieval.
#>

# Ensure required PowerShell modules are installed
$requiredModules = @("powershell-yaml", "VMware.PowerCLI")
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "$module is not installed. Install it using 'Install-Module $module'." -ForegroundColor Red
        exit 1
    }
}

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

function Global:Invoke-Addition {
    param(
        [Parameter(Mandatory)]
        [double]$a,
        [Parameter(Mandatory)]
        [double]$b
    )
    $a + $b
}

function Global:Invoke-Subtraction {
    param(
        [Parameter(Mandatory)]
        [double]$a,
        [Parameter(Mandatory)]
        [double]$b
    )
    $a - $b
}

function Global:Invoke-VM-Memory {
    param(
        [Parameter(Mandatory)]
        [string]$name
    )

    #$name = "VAA"

    try {
        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop

        # Retrieve VM details
        $vm = Get-VM -Name $name -ErrorAction SilentlyContinue
        if (-not $vm) {
            return "Error: VM '$name' not found in vCenter."
        }

        # Extract memory information
        $memoryGB = $vm.MemoryGB
        $result = "VM '$name' has $memoryGB GB of memory."

        return $result
    } catch {
        return "Error: Failed to retrieve VM information for '$name': $_"
    } finally {
        # Disconnect from vCenter
        if ($vCenter) {
            Disconnect-VIServer -Server $vCenter -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Global:Invoke-VM-CPU {
    param(
        [Parameter(Mandatory)]
        [string]$name
    )

    try {
        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop

        # Retrieve VM details
        $vm = Get-VM -Name $name -ErrorAction SilentlyContinue
        if (-not $vm) {
            return "Error: VM '$name' not found in vCenter."
        }

        # Extract CPU usage information
        $cpuUsageMHz = $vm.ExtensionData.Summary.QuickStats.OverallCpuUsage
        $numCpu = $vm.NumCpu
        $cpuMhzPerCore = $vm.ExtensionData.Runtime.MaxCpuUsage / $numCpu
        $cpuUsagePercent = [math]::Round(($cpuUsageMHz / ($numCpu * $cpuMhzPerCore)) * 100, 2)

        $result = "VM '$name' is using $cpuUsageMHz MHz of its allocated $numCpu vCPUs, which is $cpuUsagePercent% of its capacity."

        return $result
    } catch {
        return "Error: Failed to retrieve CPU usage for VM '$name': $_"
    } finally {
        # Disconnect from vCenter
        if ($vCenter) {
            Disconnect-VIServer -Server $vCenter -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Global:Invoke-vCenter-Hosts-CPU {
    param(
        [Parameter(Mandatory)]
        [string]$name
    )

    #$name = "192.168.6.103"
    try {
        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop

        # Retrieve Host details
        # Get all ESXi host names
        $vhost = Get-VMHost -Name $name #| Select-Object Name
        if (-not $vhost) {
            return "Error: VM '$name' not found in vCenter."
        }

        # Extract CPU information
        #$vhost
        $numCPU = $vhost.NumCpu
        $result = "Host '$name' has $numCPU vCPUs."

        return $result
    } catch {
        return "Error: Failed to retrieve VM information for '$name': $_"
    } finally {
        # Disconnect from vCenter
        if ($vCenter) {
            Disconnect-VIServer -Server $vCenter -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Global:Invoke-vCenter-Hosts-List {
    try {
        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop

        # Get all ESXi host names
        $hosts = Get-VMHost | Select-Object -ExpandProperty Name
        if (-not $hosts) {
            return "No hosts found in vCenter."
        }

        # Format the output
        $result = "vCenter Hosts:`n" + ($hosts -join "`n")
        return $result
    } catch {
        return "Error: Failed to retrieve host information: $_"
    } finally {
        # Disconnect from vCenter
        if ($vCenter) {
            Disconnect-VIServer -Server $vCenter -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Global:Invoke-vCenter-VM-Count {
    try {
        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop

        # Get all VMs and count them
        $vms = Get-VM
        $vmCount = $vms.Count
        $poweredOnVMs = ($vms | Where-Object {$_.PowerState -eq 'PoweredOn'}).Count

        # Format the output
        $result = "Total VMs: $vmCount`nPowered On VMs: $poweredOnVMs"
        return $result
    } catch {
        return "Error: Failed to retrieve VM information: $_"
    } finally {
        # Disconnect from vCenter
        if ($vCenter) {
            Disconnect-VIServer -Server $vCenter -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Global:Invoke-Host-VM-Count {
    param(
        [Parameter(Mandatory)]
        [string]$name
    )

    try {
        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop

        # Get the host
        $vmhost = Get-VMHost -Name $name -ErrorAction SilentlyContinue
        if (-not $vmhost) {
            return "Error: Host '$name' not found in vCenter."
        }

        # Get VMs on the host
        $vms = Get-VM -Location $vmhost
        $totalVMs = $vms.Count
        $poweredOnVMs = ($vms | Where-Object {$_.PowerState -eq 'PoweredOn'}).Count

        $result = "Host '$name' has: `nTotal VMs: $totalVMs`nPowered On VMs: $poweredOnVMs"
        return $result
    } catch {
        return "Error: Failed to retrieve VM information for host '$name': $_"
    } finally {
        # Disconnect from vCenter
        if ($vCenter) {
            Disconnect-VIServer -Server $vCenter -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Global:Invoke-vCenter-Hosts-Storage {
    param(
        [Parameter(Mandatory)]
        [string]$name
    )

    try {
        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop

        # Get the host
        $vmhost = Get-VMHost -Name $name -ErrorAction SilentlyContinue
        if (-not $vmhost) {
            return "Error: Host '$name' not found in vCenter."
        }

        # Get storage information
        $datastores = Get-Datastore -VMHost $vmhost
        $totalCapacityGB = 0
        $freeSpaceGB = 0

        foreach ($datastore in $datastores) {
            $totalCapacityGB += [math]::Round($datastore.CapacityGB, 2)
            $freeSpaceGB += [math]::Round($datastore.FreeSpaceGB, 2)
        }

        $usedSpaceGB = [math]::Round($totalCapacityGB - $freeSpaceGB, 2)
        $result = "Host '$name' storage:`nTotal Capacity: $totalCapacityGB GB`nUsed Space: $usedSpaceGB GB`nFree Space: $freeSpaceGB GB"
        return $result
    } catch {
        return "Error: Failed to retrieve storage information for host '$name': $_"
    } finally {
        # Disconnect from vCenter
        if ($vCenter) {
            Disconnect-VIServer -Server $vCenter -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Global:Invoke-vCenter-Hosts-CPU-Usage {

    # Monitor ESXi Host CPU Usage
    # Connect to vCenter Server
    try {
        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to vCenter: $_" -ForegroundColor Red
        exit
    }

    try {
        # Get all hosts from vCenter
        $vmHosts = Get-VMHost

        # Create an array to store results
        $cpuResults = @()

        foreach ($vmHost in $vmHosts) {
            $cpuInfo = $vmHost | Get-View
            $cpuUsage = [int]($cpuInfo.Summary.QuickStats.OverallCpuUsage / ($cpuInfo.Summary.Hardware.CpuMhz * $cpuInfo.Summary.Hardware.NumCpuCores) * 100)

            # Create custom object with host info and CPU usage
            $hostResult = [PSCustomObject]@{
                HostName = $vmHost.Name
                CPUUsage = $cpuUsage
            }

            # Add to results array
            $cpuResults += $hostResult
        }

        # Convert results to JSON and return
        return $cpuResults | ConvertTo-Json -Depth 10
    }
    catch {
        Write-Host "Error getting host statistics: $_" -ForegroundColor Red
    }

    # Disconnect from vCenter when script is stopped
    Disconnect-VIServer -Server * -Force -Confirm:$false
}

function Global:Invoke-vCenter-Hosts-Memory-Usage {
    try {
        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop
    } catch {
        Write-Host "Failed to connect to vCenter: $_" -ForegroundColor Red
        exit
    }

    try {
        # Get all hosts from vCenter
        $vmHosts = Get-VMHost
        
        # Create an array to store results
        $memoryResults = @()

        foreach ($vmHost in $vmHosts) {
            $memInfo = $vmHost | Get-View
            $totalMemoryGB = [math]::Round($memInfo.Summary.Hardware.MemorySize / 1GB, 2)
            $usedMemoryGB = [math]::Round($memInfo.Summary.QuickStats.OverallMemoryUsage / 1024, 2)
            $freeMemoryGB = [math]::Round($totalMemoryGB - $usedMemoryGB, 2)
            $memoryUsagePercent = [math]::Round(($usedMemoryGB / $totalMemoryGB) * 100, 1)
            
            # Create custom object with host info and memory usage
            $hostResult = [PSCustomObject]@{
                HostName = $vmHost.Name
                TotalMemoryGB = $totalMemoryGB
                UsedMemoryGB = $usedMemoryGB
                FreeMemoryGB = $freeMemoryGB
                MemoryUsage = $memoryUsagePercent
            }
            
            # Add to results array
            $memoryResults += $hostResult
        }

        # Return the results array
        return $memoryResults
    }
    catch {
        Write-Host "Error getting host memory statistics: $_" -ForegroundColor Red
    }

    # Disconnect from vCenter when script is stopped
    Disconnect-VIServer -Server * -Force -Confirm:$false
}

function Global:Invoke-VM-Tools-Version {
    [CmdletBinding()]
    param()
    
    try {
        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop

        # Retrieve all VMs
        $vms = Get-VM
        if (-not $vms) {
            return "No VMs found in vCenter."
        }

        # Create an array to store results
        $toolsVersions = @()

        foreach ($vm in $vms) {
            $toolsVersion = $vm.ExtensionData.Guest.ToolsVersion
            $toolsStatus = $vm.ExtensionData.Guest.ToolsStatus

            # Create custom object with VM name and tools version
            $vmResult = [PSCustomObject]@{
                VMName = $vm.Name
                ToolsVersion = $toolsVersion
                ToolsStatus = $toolsStatus
            }

            # Add to results array
            $toolsVersions += $vmResult
        }

        # Return the results array
        return $toolsVersions
    } catch {
        return "Error: Failed to retrieve VMware Tools version for VMs: $_"
    } finally {
        # Disconnect from vCenter
        if ($vCenter) {
            Disconnect-VIServer -Server $vCenter -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}



function Global:Invoke-VM-Tools-Version-Json {
    try {
        # Get tools versions using existing function
        $toolsVersions = Invoke-VM-Tools-Version
        
        # Convert to JSON and return
        return $toolsVersions | ConvertTo-Json
    } catch {
        return "Error: Failed to retrieve VMware Tools version for VMs as JSON: $_"
    }
}

function Global:Invoke-RVTools-Data {

    # Path to the Excel file
    $excelPath = "/Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/RVTools/RVTools_export_all_2024-08-18_15.54.15.xlsx"

    # Validate file
    if (-not (Test-Path -Path $ExcelPath)) {
        throw "Excel file '$ExcelPath' does not exist."
    }

    # Get sheet names
    $sheetNames = Get-ExcelSheetInfo -Path $ExcelPath | Select-Object -ExpandProperty Name
    if (-not $sheetNames) {
        throw "No sheets found in '$ExcelPath'."
    }

    # Prepare hashtable to store data globally (keeps in memory)
    if (-not $Script:dataStore) {
        $Script:dataStore = @{}
    } else {
        $Script:dataStore.Clear()
    }

    # Track used variable names
    $usedNames = @{}

    foreach ($sheet in $sheetNames) {
        $baseName = ($sheet -replace '[^a-zA-Z0-9]', '')
        $varName = $baseName
        $counter = 1
        while ($usedNames.ContainsKey($varName)) {
            $varName = "$baseName`_$counter"
            $counter++
        }
        $usedNames[$varName] = $true

        try {
            $sheetData = Import-Excel -Path $ExcelPath -WorksheetName $sheet

            if (-not $sheetData -or $sheetData.Count -eq 0) {
                $sheetData = [pscustomobject]@{ Note = "No Data" }
                Write-Host "Sheet '$sheet' is empty. Added 'No Data'."
            }
            else {
                # Fix duplicate column names
                $columns = $sheetData | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
                $columnTracker = @{}
                foreach ($col in $columns) {
                    if ($columnTracker.ContainsKey($col)) {
                        $index = ++$columnTracker[$col]
                        $newCol = "$col-$index"
                        foreach ($row in $sheetData) {
                            $row | Add-Member -MemberType NoteProperty -Name $newCol -Value $row.$col -Force
                            $row.PSObject.Properties.Remove($col)
                        }
                    } else {
                        $columnTracker[$col] = 0
                    }
                }
            }
        }
        catch {
            if ($_.Exception.Message -like "*Duplicate column headers*") {
                Write-Warning "Sheet '$sheet' has duplicate headers. Substituting with error message."
                $sheetData = [pscustomobject]@{ Error = "Duplicate column headers" }
            } else {
                Write-Warning "Failed to import sheet '$sheet': $($_.Exception.Message)"
                $sheetData = [pscustomobject]@{ Error = $_.Exception.Message }
            }
        }

        # Store in memory
        $Script:dataStore[$sheet] = $sheetData

        # Also create a variable if you want
        New-Variable -Name $varName -Value $sheetData -Scope Global -Force

        Write-Host "Processed sheet '$sheet' into variable '$varName'. Row count: $($sheetData.Count)"
    }

    # Extract VM names from vInfo worksheet if it exists
    if ($Script:dataStore.ContainsKey("vInfo")) {
        $vmNames = $Script:dataStore["vInfo"] | Select-Object -ExpandProperty VM
        Write-Host "Found the following VMs in vInfo worksheet:"
        $vmNames | ForEach-Object { Write-Host "- $_" }
    }

    # Return the full datastore
    return $Script:dataStore
}


function Global:Invoke-vCenter-VM-List {
    try {
        # Connect to vCenter
        $vCenter = Connect-VIServer -Server $cfg.vCenter.server -User $cfg.vCenter.username -Password $cfg.vCenter.password -Protocol https -ErrorAction Stop

        # Get all VM names
        $vms = Get-VM | Select-Object Name, PowerState | Sort-Object Name
        if (-not $vms) {
            return "No VMs found in vCenter."
        }

        # Format the output
        $result = "VM Names and Power States:`n"
        $result += "==========================`n"
        foreach ($vm in $vms) {
            $result += "- $($vm.Name) ($($vm.PowerState))`n"
        }
        $result += "`nTotal VMs: $($vms.Count)"
        return $result
    } catch {
        return "Error: Failed to retrieve VM list: $_"
    } finally {
        # Disconnect from vCenter
        if ($vCenter) {
            Disconnect-VIServer -Server $vCenter -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Global:Invoke-VROPS-VM-Data {
    param(
        [Parameter(Mandatory)]
        [string]$vmName
    )


    $opsURL      = "https://vao.vcrocs.local"
    $opsUsername = "admin"
    $opsPassword = "VMware1!"
    #$vmName      = "DC-02"
    $authSource  = "local"


    # ----- Get Aria Operations token
    $uri = "$opsURL/suite-api/api/auth/token/acquire?_no_links=true"
    #$uri

    # --- Create body
    $bodyHashtable = @{
        username = $opsUsername
        authSource = $authSource
        password = $opsPassword
    }

    # --- Convert the hashtable to a JSON string
    $body = $bodyHashtable | ConvertTo-Json

    $token = Invoke-RestMethod -Uri $uri -Method Post -Headers @{
        "accept" = "application/json"
        "Content-Type" = "application/json"
    } -Body $body -SkipCertificateCheck

    #$token.token

    $authorization = "OpsToken " + $token.token
    #$authorization


    # ----- Get the VM Operations identifier
    #$uri = "$opsURL/suite-api/api/resources?maintenanceScheduleId=&name=$vmName&page=0&pageSize=1000&_no_links=true"
    $uri = "$opsURL/suite-api/api/resources?name=$vmName&page=0&pageSize=1000&_no_links=true"
    #$uri

    $identifier = Invoke-RestMethod -Uri $uri -Method Get -Headers @{
        "accept" = "application/json"
        "Authorization" = $authorization
    } -SkipCertificateCheck

    #$identifier
    $identifier = $identifier.resourceList
    $json = $identifier | ConvertTo-Json -Depth 10
    #$json

    # Convert the JSON string to a PowerShell object
    $data = $json | ConvertFrom-Json

    # Search for the object where resourceKindKey is "VirtualMachine"
    $targetResourceKindKey = "VirtualMachine"
    $matchedObject = $data | Where-Object { $_.resourceKey.resourceKindKey -eq $targetResourceKindKey }

    # If a matching object is found, output the identifier
    if ($matchedObject) {
        $vmIdentifier = $($matchedObject.identifier)
        #Write-Output $($matchedObject.identifier)
    } # End If
    else {
        Write-Output "No VirtualMachine resourceKindKey found"
    } # End Else

    #$vmIdentifier


    # ----- Get Field Names and Values
    $uri = "$opsURL/suite-api/api/resources/properties?resourceId=$vmidentifier&_no_links=true"
    #$uri

    $resourcePropertiesList = Invoke-RestMethod -Uri $uri -Method Get -Headers @{
        "accept" = "application/json"
        "Authorization" = $authorization
    } -SkipCertificateCheck

    $outPut = $resourcePropertiesList.resourcePropertiesList.property
    return $outPut

} # End function





# Script Tests
# Invoke-vCenter-Hosts-CPU -name "192.168.6.104"

#$excelPath = "/Users/dalehassinger/Documents/GitHub/PS-TAM-Lab/RVTools/RVTools_export_all_2024-08-18_15.54.15.xlsx"
#Import-ExcelAllSheetsToMemory -ExcelPath $excelPath

# Start the MCP server with the defined tools
Start-McpServer Invoke-Addition, Invoke-Subtraction, Invoke-VM-Memory, Invoke-VM-CPU, Invoke-vCenter-Hosts-CPU, Invoke-vCenter-Hosts-List, Invoke-vCenter-VM-Count, Invoke-Host-VM-Count, Invoke-vCenter-Hosts-Storage, Invoke-vCenter-Hosts-CPU-Usage, Invoke-vCenter-Hosts-Memory-Usage, Invoke-VM-Tools-Version, Invoke-VM-Tools-Version-Json, Invoke-RVTools-Data, Invoke-VROPS-VM-Data, Invoke-vCenter-VM-List


<#
Sample Prompts:

show me all the vmware tools versions and return the results as json
show me vcenter hosts cpu usage
show me vcenter hosts memory usage

#>