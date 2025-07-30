from mcp.server.fastmcp import FastMCP, Context
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import dataclass
import asyncio
import subprocess
import os
import sys
import json
import tempfile
import uuid

# vCenter Configuration
VCENTER_CONFIG = {
    "host": "192.168.6.100",
    "user": "administrator@vcrocs.local",
    "password": "VMware1!"
}

def get_vcenter_connection():
    """Get a connection to vCenter with SSL context."""
    import ssl
    try:
        from pyVim import connect
        from pyVmomi import vim
    except ImportError:
        raise ImportError("PyVmomi library not installed. Run 'pip install pyvmomi' to install it.")
    
    # Disable SSL certificate verification (for lab environments)
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_NONE
    
    # Connect to vCenter
    service_instance = connect.SmartConnect(
        host=VCENTER_CONFIG["host"],
        user=VCENTER_CONFIG["user"],
        pwd=VCENTER_CONFIG["password"],
        sslContext=context
    )
    
    return service_instance

# Create a dataclass for our PowerShell application context
@dataclass
class PowerShellContext:
    """Context for the PowerShell MCP server."""
    ps_path: str

@asynccontextmanager
async def powershell_lifespan(server: FastMCP) -> AsyncIterator[PowerShellContext]:
    """
    Sets up the PowerShell environment.
    
    Args:
        server: The FastMCP server instance
        
    Yields:
        PowerShellContext: The context containing PowerShell configuration
    """
    # Determine PowerShell path based on platform
    if sys.platform == "win32":
        ps_path = "powershell.exe"
    else:
        ps_path = "pwsh"  # For Linux/MacOS
    
    # Verify PowerShell is installed
    try:
        subprocess.run([ps_path, "-Command", "Write-Host 'PowerShell is available'"], 
                      check=True, capture_output=True)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print(f"Error: PowerShell is not available: {e}")
        print("Please install PowerShell Core (pwsh) for your platform")
        sys.exit(1)
    
    try:
        yield PowerShellContext(ps_path=ps_path)
    finally:
        # No explicit cleanup needed
        pass

# Initialize FastMCP server with increased timeout
mcp = FastMCP(
    "mcp-vcROCS",
    description="MCP server for executing vCROCS VMware Operations",
    lifespan=powershell_lifespan,
    host=os.getenv("HOST", "0.0.0.0"),
    port=os.getenv("PORT", "8050"),
    tool_timeout=300  # Increase default tool timeout to 5 minutes
)

async def execute_powershell_script(ps_path: str, script_path: str, timeout: int = 180):
    """
    Execute PowerShell script and return the results.
    
    Args:
        ps_path: Path to PowerShell executable
        script_path: Path to the PowerShell script file
        timeout: Maximum execution time in seconds (default: 180)
    
    Returns:
        dict: Script execution results including stdout, stderr, and exit code
    """
    print(f"Starting execution of {script_path} with timeout {timeout}s")
    start_time = asyncio.get_event_loop().time()
    
    try:
        # Check if file exists before executing
        if not os.path.isfile(script_path):
            print(f"ERROR: Script file not found: {script_path}")
            return {
                "stdout": "",
                "stderr": f"Script file not found: {script_path}",
                "exit_code": -1
            }
            
        print(f"Script file exists, launching process with {ps_path}")
        process = await asyncio.create_subprocess_exec(
            ps_path,
            "-File", script_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            print(f"Waiting for process output with timeout {timeout}s")
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            
            elapsed = asyncio.get_event_loop().time() - start_time
            print(f"Process completed in {elapsed:.2f}s with exit code {process.returncode}")
            
            return {
                "stdout": stdout.decode('utf-8', errors='replace').strip(),
                "stderr": stderr.decode('utf-8', errors='replace').strip(),
                "exit_code": process.returncode
            }
        except asyncio.TimeoutError:
            elapsed = asyncio.get_event_loop().time() - start_time
            print(f"ERROR: Process timed out after {elapsed:.2f}s")
            try:
                print("Killing timed out process")
                process.kill()
            except Exception as e:
                print(f"Error killing process: {e}")
            
            return {
                "stdout": "",
                "stderr": f"Command execution timed out after {timeout} seconds",
                "exit_code": -1
            }
            
    except Exception as e:
        elapsed = asyncio.get_event_loop().time() - start_time
        print(f"ERROR: Exception after {elapsed:.2f}s: {e}")
        return {
            "stdout": "",
            "stderr": f"Error executing PowerShell script: {str(e)}",
            "exit_code": -1
        }

@mcp.tool()
async def welcome(ctx: Context) -> dict:
    """Get a welcome message from the vCROCS MCP server.
    
    This tool returns a simple welcome message to confirm the server is running.
    
    Args:
        ctx: The MCP server provided context
        
    Returns:
        A welcome message
    """
    # Return a dictionary directly instead of JSON string
    return {
        "message": "Welcome to the MCP Server by vCROCS!",
        "status": "online"
    }

@mcp.tool()
async def server_info(ctx: Context) -> dict:
    """Get basic information about the server environment.
    
    This tool returns system information without executing any PowerShell scripts.
    Use this to verify basic MCP functionality.
    
    Args:
        ctx: The MCP server provided context
        
    Returns:
        Basic server information
    """
    import platform
    
    try:
        return {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "processor": platform.processor(),
            "hostname": platform.node(),
            "mcp_version": getattr(mcp, "__version__", "unknown"),
            "powershell_path": ctx.request_context.lifespan_context.ps_path
        }
    except Exception as e:
        # Simple error handling to avoid timeouts
        return {"error": f"Error getting server info: {str(e)}"}

@mcp.tool()
async def get_vcenter_vms(ctx: Context, timeout: int = 180) -> dict:
    """Get comprehensive information about all VMs from vCenter.
    
    This tool connects to vCenter and retrieves detailed information about all virtual machines,
    including hardware configuration, performance metrics, storage, and network details.
    
    Args:
        ctx: The MCP server provided context
        timeout: Maximum execution time in seconds (default: 180)
        
    Returns:
        Comprehensive information about all VMs in the vCenter environment
    """
    try:
        # Run in a separate thread to avoid blocking the event loop
        return await asyncio.get_event_loop().run_in_executor(None, get_vcenter_vms_sync)
    except Exception as e:
        print(f"Error in get_vcenter_vms: {str(e)}")
        return {
            "error": f"Failed to get vCenter VMs: {str(e)}",
            "status": "failed"
        }

def get_vcenter_vms_sync() -> dict:
    """Synchronous function to get comprehensive VM details using PyVmomi.
    
    Returns:
        A dictionary containing detailed VM information or error details
    """
    try:
        # Try to import PyVmomi - install using "pip install pyvmomi" if needed
        import ssl
        try:
            from pyVim import connect
            from pyVmomi import vim
        except ImportError:
            return {
                "error": "PyVmomi library not installed. Run 'pip install pyvmomi' to install it.",
                "status": "failed"
            }
        
        # Use reusable connection function
        # Log connection attempt to file instead of print for debugging
        with open("/tmp/vcenter_debug.log", "a") as log:
            log.write(f"Connecting to vCenter server {VCENTER_CONFIG['host']}...\n")
        
        try:
            service_instance = get_vcenter_connection()
        except Exception as connection_error:
            return {
                "error": f"Failed to connect to vCenter: {str(connection_error)}",
                "status": "connection_failed"
            }
        
        # Log connection success to file instead of stdout
        with open("/tmp/vcenter_debug.log", "a") as log:
            log.write("Connected to vCenter. Retrieving VM information...\n")
        
        # Get the content property
        content = service_instance.RetrieveContent()
        
        # Get the container view for VMs
        container = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.VirtualMachine], True
        )
        
        # Collect comprehensive VM information
        vms_info = []
        for vm in container.view:
            # Skip vCLS VMs
            if vm.name.startswith("vcls-"):
                continue
                
            # Get host name
            host_name = vm.runtime.host.name if vm.runtime.host else "Unknown"
            
            # Get guest OS details
            guest_full_name = vm.config.guestFullName if hasattr(vm.config, "guestFullName") else "Unknown"
            
            # Build comprehensive VM information
            vm_info = {
                # Basic information
                "Name": vm.name,
                "MOID": vm._moId,
                "UUID": vm.config.uuid if hasattr(vm.config, "uuid") else None,
                "InstanceUUID": vm.config.instanceUuid if hasattr(vm.config, "instanceUuid") else None,
                "GuestFullName": guest_full_name,
                "GuestId": vm.config.guestId if hasattr(vm.config, "guestId") else None,
                "Annotation": vm.config.annotation if hasattr(vm.config, "annotation") else None,
                
                # Hardware configuration
                "NumCpu": vm.config.hardware.numCPU,
                "NumCoresPerSocket": vm.config.hardware.numCoresPerSocket if hasattr(vm.config.hardware, "numCoresPerSocket") else None,
                "MemoryGB": vm.config.hardware.memoryMB / 1024,
                "MemoryHotAddEnabled": vm.config.memoryHotAddEnabled if hasattr(vm.config, "memoryHotAddEnabled") else None,
                "CpuHotAddEnabled": vm.config.cpuHotAddEnabled if hasattr(vm.config, "cpuHotAddEnabled") else None,
                "CpuHotRemoveEnabled": vm.config.cpuHotRemoveEnabled if hasattr(vm.config, "cpuHotRemoveEnabled") else None,
                
                # Runtime state
                "PowerState": str(vm.runtime.powerState),
                "ConnectionState": str(vm.runtime.connectionState),
                "BootTime": str(vm.runtime.bootTime) if vm.runtime.bootTime else None,
                "ToolsStatus": str(vm.guest.toolsStatus) if hasattr(vm.guest, "toolsStatus") else "Unknown",
                "ToolsRunningStatus": str(vm.guest.toolsRunningStatus) if hasattr(vm.guest, "toolsRunningStatus") else "Unknown",
                "ToolsVersionStatus": str(vm.guest.toolsVersionStatus) if hasattr(vm.guest, "toolsVersionStatus") else "Unknown",
                
                # Resource usage
                "OverallCpuUsage": vm.summary.quickStats.overallCpuUsage if hasattr(vm.summary.quickStats, "overallCpuUsage") else None,
                "OverallCpuDemand": vm.summary.quickStats.overallCpuDemand if hasattr(vm.summary.quickStats, "overallCpuDemand") else None,
                "GuestMemoryUsage": vm.summary.quickStats.guestMemoryUsage if hasattr(vm.summary.quickStats, "guestMemoryUsage") else None,
                "HostMemoryUsage": vm.summary.quickStats.hostMemoryUsage if hasattr(vm.summary.quickStats, "hostMemoryUsage") else None,
                
                # Host information
                "Host": host_name,
                "ClusterName": vm.runtime.host.parent.name if vm.runtime.host and hasattr(vm.runtime.host.parent, "name") else None,
                
                # Storage information
                "ProvisionedSpaceGB": vm.summary.storage.committed / 1073741824 if hasattr(vm.summary.storage, "committed") else None,
                "UncommittedSpaceGB": vm.summary.storage.uncommitted / 1073741824 if hasattr(vm.summary.storage, "uncommitted") else None,
                
                # Network details
                "IPAddresses": vm.guest.ipAddress if hasattr(vm.guest, "ipAddress") else None,
                "HostName": vm.guest.hostName if hasattr(vm.guest, "hostName") else None,
                
                # Additional configuration
                "Template": vm.config.template if hasattr(vm.config, "template") else False,
                "ChangeVersion": vm.config.changeVersion if hasattr(vm.config, "changeVersion") else None,
                "CreateDate": vm.config.createDate if hasattr(vm.config, "createDate") else None,
                "Modified": vm.config.modified if hasattr(vm.config, "modified") else None
            }
            
            # Get network adapters
            network_adapters = []
            if hasattr(vm, "network"):
                for i, network in enumerate(vm.network):
                    network_adapters.append({
                        "NetworkName": network.name,
                        "NetworkType": type(network).__name__
                    })
            vm_info["NetworkAdapters"] = network_adapters
            
            # Get virtual disks
            disks = []
            for device in vm.config.hardware.device:
                if isinstance(device, vim.vm.device.VirtualDisk):
                    disks.append({
                        "Label": device.deviceInfo.label,
                        "CapacityGB": device.capacityInKB / 1048576,
                        "DiskMode": device.backing.diskMode if hasattr(device.backing, "diskMode") else None,
                        "Datastore": device.backing.datastore.name if hasattr(device.backing, "datastore") else None,
                        "FileName": device.backing.fileName if hasattr(device.backing, "fileName") else None,
                        "Thin": device.backing.thinProvisioned if hasattr(device.backing, "thinProvisioned") else None
                    })
            vm_info["Disks"] = disks
            
            # Get snapshots (if any)
            snapshots = []
            if vm.snapshot and vm.snapshot.rootSnapshotList:
                for snapshot in vm.snapshot.rootSnapshotList:
                    snapshots.append({
                        "Name": snapshot.name,
                        "Description": snapshot.description,
                        "CreateTime": str(snapshot.createTime),
                        "State": snapshot.state
                    })
            vm_info["Snapshots"] = snapshots
            
            # Add to the list
            vms_info.append(vm_info)
        
        # Sort by name
        vms_info.sort(key=lambda x: x["Name"])
        
        # Disconnect from vCenter
        connect.Disconnect(service_instance)
        
        return {
            "vms": vms_info,
            "count": len(vms_info),
            "status": "success"
        }
        
    except Exception as e:
        # Use log file instead of print for error logging
        with open("/tmp/vcenter_debug.log", "a") as log:
            log.write(f"Error retrieving VM information: {str(e)}\n")
        
        return {
            "error": f"Error retrieving VM information: {str(e)}",
            "status": "failed"
        }

# Fix the function name - this appears to be missing the underscore prefix
def get_vcenter_hosts_sync() -> dict:
    """Synchronous function to get vCenter hosts using PyVmomi.
    
    Returns:
        A dictionary containing host information or error details
    """
    try:
        # Try to import PyVmomi - install using "pip install pyvmomi" if needed
        import ssl
        try:
            from pyVim import connect
            from pyVmomi import vim
        except ImportError:
            return {
                "error": "PyVmomi library not installed. Run 'pip install pyvmomi' to install it.",
                "status": "failed"
            }
        
        # Use reusable connection function
        try:
            service_instance = get_vcenter_connection()
        except Exception as connection_error:
            return {
                "error": f"Failed to connect to vCenter: {str(connection_error)}",
                "status": "connection_failed"
            }
        
        # Get the content property
        content = service_instance.RetrieveContent()
        
        # Get the container view for HostSystem
        container = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.HostSystem], True
        )
        
        # Collect host information
        hosts_info = []
        for host in container.view:
            # Extract various properties from the host
            host_info = {
                # Basic information
                "Name": host.name,
                "Model": host.hardware.systemInfo.model,
                "Vendor": host.hardware.systemInfo.vendor,
                "ProcessorModel": host.hardware.cpuPkg[0].description if hasattr(host.hardware, 'cpuPkg') and len(host.hardware.cpuPkg) > 0 else "Unknown",
                "Version": host.config.product.version,
                "Build": host.config.product.build,
                
                # Hardware details
                "NumCpuPkgs": host.hardware.cpuInfo.numCpuPackages,
                "NumCpuCores": host.hardware.cpuInfo.numCpuCores,
                "NumCpuThreads": host.hardware.cpuInfo.numCpuThreads,
                "CpuMhz": host.hardware.cpuInfo.hz / 1000000,
                "MemorySize": host.hardware.memorySize / 1073741824,  # Convert to GB
                
                # Network information
                "NumNics": len(host.config.network.pnic) if hasattr(host.config.network, "pnic") else 0,
                
                # Storage information
                "NumDatastores": len(host.datastore),
                
                # Status
                "ConnectionState": str(host.runtime.connectionState),
                "PowerState": str(host.runtime.powerState),
                "MaintenanceMode": host.runtime.inMaintenanceMode,
                
                # Performance metrics
                "OverallStatus": str(host.overallStatus),
                "CpuUsageMhz": host.summary.quickStats.overallCpuUsage,
                "MemoryUsageGB": host.summary.quickStats.overallMemoryUsage / 1024,  # Convert to GB
                
                # Configuration
                "ClusterName": host.parent.name if hasattr(host.parent, "name") else "Standalone",
                "VmCount": len(host.vm),
                
                # Additional details
                "UUID": host.hardware.systemInfo.uuid,
                "BootTime": str(host.runtime.bootTime) if host.runtime.bootTime else None
            }
            
            # Get management IPs - fixing the access method to avoid the error
            management_ips = []
            try:
                # Try multiple approaches to get host IPs
                # First try network config
                if hasattr(host, "config") and hasattr(host.config, "virtualNicManagerInfo"):
                    for vnic_manager in host.config.virtualNicManagerInfo.netConfig:
                        for vnic in vnic_manager.candidateVnic:
                            if hasattr(vnic.spec, "ip") and hasattr(vnic.spec.ip, "ipAddress"):
                                management_ips.append(vnic.spec.ip.ipAddress)
                
                # If no IPs found, try host's network config directly
                if not management_ips and hasattr(host, "config") and hasattr(host.config, "network"):
                    if hasattr(host.config.network, "vnic"):
                        for vnic in host.config.network.vnic:
                            if hasattr(vnic.spec, "ip") and hasattr(vnic.spec.ip, "ipAddress"):
                                management_ips.append(vnic.spec.ip.ipAddress)
            except Exception:
                # Silently handle any errors in IP address collection
                pass
            
            host_info["ManagementIPs"] = management_ips
            
            # Get datastores
            datastores = []
            for ds in host.datastore:
                datastores.append({
                    "Name": ds.name,
                    "Capacity": ds.summary.capacity / 1073741824,  # Convert to GB
                    "FreeSpace": ds.summary.freeSpace / 1073741824,  # Convert to GB
                    "Type": ds.summary.type
                })
            host_info["Datastores"] = datastores
            
            # Get networks
            networks = []
            for network in host.network:
                networks.append({
                    "Name": network.name,
                    "Accessible": network.summary.accessible
                })
            host_info["Networks"] = networks
            
            # Get VM names
            host_info["VMs"] = [vm.name for vm in host.vm]
            
            hosts_info.append(host_info)
        
        # Sort by name
        hosts_info.sort(key=lambda x: x["Name"])
        
        # Disconnect from vCenter
        connect.Disconnect(service_instance)
        
        return {
            "hosts": hosts_info,
            "count": len(hosts_info),
            "status": "success"
        }
        
    except Exception as e:
        # Use log file instead of print for error logging
        with open("/tmp/vcenter_debug.log", "a") as log:
            log.write(f"Error retrieving host information: {str(e)}\n")
        
        return {
            "error": f"Error retrieving host information: {str(e)}",
            "status": "failed"
        }

@mcp.tool()
async def get_vcenter_hosts(ctx: Context, timeout: int = 180) -> dict:
    """Get detailed information about all ESXi hosts in vCenter.
    
    This tool connects to vCenter and returns comprehensive information about all hosts,
    including hardware details, configuration, and performance metrics.
    
    Args:
        ctx: The MCP server provided context
        timeout: Maximum execution time in seconds (default: 180)
        
    Returns:
        Detailed information about all vCenter hosts
    """
    try:
        # Run in a separate thread to avoid blocking the event loop
        return await asyncio.get_event_loop().run_in_executor(None, get_vcenter_hosts_sync)
    except Exception as e:
        # Don't print directly to stdout
        with open("/tmp/vcenter_debug.log", "a") as log:
            log.write(f"Error in get_vcenter_hosts: {str(e)}\n")
        
        return {
            "error": f"Failed to get vCenter hosts: {str(e)}",
            "status": "failed"
        }

@mcp.tool()
async def get_vcenter_infrastructure(ctx: Context, object_type: str = "datacenter", object_name: str = "", timeout: int = 180) -> dict:
    """Get specific vCenter infrastructure information based on object type and name.
    
    This tool allows you to explore vCenter infrastructure by querying specific objects.
    You can get information about datacenters, clusters, resource pools, folders, and more.
    
    Args:
        ctx: The MCP server provided context
        object_type: Type of object to query. Options: "datacenter", "cluster", "resourcepool", "folder", "datastore", "network", "overview"
        object_name: Name of the specific object (leave empty to list all objects of that type)
        timeout: Maximum execution time in seconds (default: 180)
        
    Returns:
        Information about the requested vCenter infrastructure objects
    """
    try:
        # Run in a separate thread to avoid blocking the event loop
        return await asyncio.get_event_loop().run_in_executor(
            None, get_vcenter_infrastructure_sync, object_type, object_name
        )
    except Exception as e:
        with open("/tmp/vcenter_debug.log", "a") as log:
            log.write(f"Error in get_vcenter_infrastructure: {str(e)}\n")
        
        return {
            "error": f"Failed to get vCenter infrastructure: {str(e)}",
            "status": "failed"
        }

def get_vcenter_infrastructure_sync(object_type: str = "datacenter", object_name: str = "") -> dict:
    """Synchronous function to get vCenter infrastructure information using PyVmomi.
    
    Args:
        object_type: Type of object to query
        object_name: Name of the specific object
        
    Returns:
        A dictionary containing infrastructure information or error details
    """
    try:
        # Try to import PyVmomi
        import ssl
        try:
            from pyVim import connect
            from pyVmomi import vim
        except ImportError:
            return {
                "error": "PyVmomi library not installed. Run 'pip install pyvmomi' to install it.",
                "status": "failed"
            }
        
        # Use reusable connection function
        with open("/tmp/vcenter_debug.log", "a") as log:
            log.write(f"Connecting to vCenter for {object_type} query...\n")
        
        try:
            service_instance = get_vcenter_connection()
        except Exception as connection_error:
            return {
                "error": f"Failed to connect to vCenter: {str(connection_error)}",
                "status": "connection_failed"
            }
        
        # Get the content property
        content = service_instance.RetrieveContent()
        
        result = {}
        
        if object_type.lower() == "overview":
            # Get overview of entire vCenter
            result = get_vcenter_overview(content)
            
        elif object_type.lower() == "datacenter":
            # Get datacenter information
            result = get_datacenter_info(content, object_name)
            
        elif object_type.lower() == "cluster":
            # Get cluster information
            result = get_cluster_info(content, object_name)
            
        elif object_type.lower() == "resourcepool":
            # Get resource pool information
            result = get_resourcepool_info(content, object_name)
            
        elif object_type.lower() == "folder":
            # Get folder information
            result = get_folder_info(content, object_name)
            
        elif object_type.lower() == "datastore":
            # Get datastore information
            result = get_datastore_info(content, object_name)
            
        elif object_type.lower() == "network":
            # Get network information
            result = get_network_info(content, object_name)
            
        else:
            result = {
                "error": f"Unsupported object type: {object_type}. Supported types: datacenter, cluster, resourcepool, folder, datastore, network, overview",
                "status": "failed"
            }
        
        # Disconnect from vCenter
        connect.Disconnect(service_instance)
        
        return result
        
    except Exception as e:
        with open("/tmp/vcenter_debug.log", "a") as log:
            log.write(f"Error retrieving infrastructure information: {str(e)}\n")
        
        return {
            "error": f"Error retrieving infrastructure information: {str(e)}",
            "status": "failed"
        }

def get_vcenter_overview(content) -> dict:
    """Get overview of entire vCenter infrastructure."""
    from pyVmomi import vim
    
    # Get counts of different object types
    datacenters = content.viewManager.CreateContainerView(content.rootFolder, [vim.Datacenter], True)
    clusters = content.viewManager.CreateContainerView(content.rootFolder, [vim.ClusterComputeResource], True)
    hosts = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)
    vms = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    datastores = content.viewManager.CreateContainerView(content.rootFolder, [vim.Datastore], True)
    
    # Filter out vCLS VMs
    vm_count = len([vm for vm in vms.view if not vm.name.startswith("vcls-")])
    
    return {
        "vcenter_overview": {
            "vcenter_name": content.about.instanceUuid,
            "version": content.about.version,
            "build": content.about.build,
            "datacenter_count": len(datacenters.view),
            "cluster_count": len(clusters.view),
            "host_count": len(hosts.view),
            "vm_count": vm_count,
            "datastore_count": len(datastores.view)
        },
        "datacenters": [dc.name for dc in datacenters.view],
        "clusters": [cluster.name for cluster in clusters.view],
        "status": "success"
    }

def get_datacenter_info(content, dc_name: str = "") -> dict:
    """Get datacenter information."""
    from pyVmomi import vim
    
    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.Datacenter], True)
    
    if dc_name:
        # Get specific datacenter
        for dc in container.view:
            if dc.name.lower() == dc_name.lower():
                return get_datacenter_details(dc)
        return {"error": f"Datacenter '{dc_name}' not found", "status": "failed"}
    else:
        # Get all datacenters
        datacenters = []
        for dc in container.view:
            datacenters.append(get_datacenter_details(dc))
        return {"datacenters": datacenters, "count": len(datacenters), "status": "success"}

def get_datacenter_details(dc) -> dict:
    """Get detailed information about a datacenter."""
    from pyVmomi import vim
    
    # Get clusters in this datacenter
    clusters = []
    if hasattr(dc.hostFolder, 'childEntity'):
        for entity in dc.hostFolder.childEntity:
            if isinstance(entity, vim.ClusterComputeResource):
                clusters.append({
                    "name": entity.name,
                    "host_count": len(entity.host),
                    "total_cpu_cores": sum([host.hardware.cpuInfo.numCpuCores for host in entity.host]),
                    "total_memory_gb": sum([host.hardware.memorySize / 1073741824 for host in entity.host])
                })
    
    # Get datastores in this datacenter
    datastores = []
    for ds in dc.datastore:
        datastores.append({
            "name": ds.name,
            "capacity_gb": ds.summary.capacity / 1073741824,
            "free_space_gb": ds.summary.freeSpace / 1073741824,
            "type": ds.summary.type
        })
    
    return {
        "name": dc.name,
        "clusters": clusters,
        "datastores": datastores,
        "networks": [net.name for net in dc.network]
    }

def get_cluster_info(content, cluster_name: str = "") -> dict:
    """Get cluster information."""
    from pyVmomi import vim
    
    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.ClusterComputeResource], True)
    
    if cluster_name:
        # Get specific cluster
        for cluster in container.view:
            if cluster.name.lower() == cluster_name.lower():
                return get_cluster_details(cluster)
        return {"error": f"Cluster '{cluster_name}' not found", "status": "failed"}
    else:
        # Get all clusters
        clusters = []
        for cluster in container.view:
            clusters.append(get_cluster_details(cluster))
        return {"clusters": clusters, "count": len(clusters), "status": "success"}

def get_cluster_details(cluster) -> dict:
    """Get detailed information about a cluster."""
    hosts_info = []
    for host in cluster.host:
        hosts_info.append({
            "name": host.name,
            "connection_state": str(host.runtime.connectionState),
            "power_state": str(host.runtime.powerState),
            "cpu_cores": host.hardware.cpuInfo.numCpuCores,
            "memory_gb": host.hardware.memorySize / 1073741824,
            "vm_count": len(host.vm)
        })
    
    return {
        "name": cluster.name,
        "datacenter": cluster.parent.parent.name,
        "host_count": len(cluster.host),
        "hosts": hosts_info,
        "total_cpu_cores": sum([host.hardware.cpuInfo.numCpuCores for host in cluster.host]),
        "total_memory_gb": sum([host.hardware.memorySize / 1073741824 for host in cluster.host]),
        "ha_enabled": cluster.configuration.dasConfig.enabled if hasattr(cluster.configuration, 'dasConfig') else None,
        "drs_enabled": cluster.configuration.drsConfig.enabled if hasattr(cluster.configuration, 'drsConfig') else None
    }

def get_resourcepool_info(content, rp_name: str = "") -> dict:
    """Get resource pool information."""
    from pyVmomi import vim
    
    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.ResourcePool], True)
    
    if rp_name:
        # Get specific resource pool
        for rp in container.view:
            if rp.name.lower() == rp_name.lower():
                return get_resourcepool_details(rp)
        return {"error": f"Resource Pool '{rp_name}' not found", "status": "failed"}
    else:
        # Get all resource pools
        resource_pools = []
        for rp in container.view:
            resource_pools.append(get_resourcepool_details(rp))
        return {"resource_pools": resource_pools, "count": len(resource_pools), "status": "success"}

def get_resourcepool_details(rp) -> dict:
    """Get detailed information about a resource pool."""
    return {
        "name": rp.name,
        "cpu_allocation": {
            "reservation": rp.config.cpuAllocation.reservation,
            "limit": rp.config.cpuAllocation.limit,
            "shares": rp.config.cpuAllocation.shares.shares
        },
        "memory_allocation": {
            "reservation": rp.config.memoryAllocation.reservation,
            "limit": rp.config.memoryAllocation.limit,
            "shares": rp.config.memoryAllocation.shares.shares
        },
        "vm_count": len(rp.vm),
        "vms": [vm.name for vm in rp.vm if not vm.name.startswith("vcls-")]
    }

def get_folder_info(content, folder_name: str = "") -> dict:
    """Get folder information."""
    from pyVmomi import vim
    
    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.Folder], True)
    
    folders = []
    for folder in container.view:
        if folder_name and folder.name.lower() != folder_name.lower():
            continue
            
        folder_info = {
            "name": folder.name,
            "type": "VM Folder" if hasattr(folder, 'childType') and vim.VirtualMachine in folder.childType else "Host Folder",
            "children": []
        }
        
        if hasattr(folder, 'childEntity'):
            for child in folder.childEntity:
                child_info = {"name": child.name, "type": type(child).__name__}
                folder_info["children"].append(child_info)
        
        folders.append(folder_info)
    
    if folder_name:
        return folders[0] if folders else {"error": f"Folder '{folder_name}' not found", "status": "failed"}
    else:
        return {"folders": folders, "count": len(folders), "status": "success"}

def get_datastore_info(content, ds_name: str = "") -> dict:
    """Get datastore information."""
    from pyVmomi import vim
    
    container = content.viewManager.CreateContainerView(content.rootFolder, [vim.Datastore], True)
    
    if ds_name:
        # Get specific datastore
        for ds in container.view:
            if ds.name.lower() == ds_name.lower():
                return get_datastore_details(ds)
        return {"error": f"Datastore '{ds_name}' not found", "status": "failed"}
    else:
        # Get all datastores
        datastores = []
        for ds in container.view:
            datastores.append(get_datastore_details(ds))
        return {"datastores": datastores, "count": len(datastores), "status": "success"}

def get_datastore_details(ds) -> dict:
    """Get detailed information about a datastore."""
    return {
        "name": ds.name,
        "type": ds.summary.type,
        "capacity_gb": ds.summary.capacity / 1073741824,
        "free_space_gb": ds.summary.freeSpace / 1073741824,
        "used_space_gb": (ds.summary.capacity - ds.summary.freeSpace) / 1073741824,
        "accessible": ds.summary.accessible,
        "url": ds.summary.url,
        "host_count": len(ds.host),
        "vm_count": len(ds.vm)
    }

def get_network_info(content, net_name: str = "") -> dict:
    """Get network information."""
    from pyVmomi import vim
    
    # Get both standard and distributed networks
    networks = []
    
    # Standard networks
    std_networks = content.viewManager.CreateContainerView(content.rootFolder, [vim.Network], True)
    for net in std_networks.view:
        if net_name and net.name.lower() != net_name.lower():
            continue
            
        network_info = {
            "name": net.name,
            "type": "Standard Network",
            "accessible": net.summary.accessible,
            "host_count": len(net.host) if hasattr(net, 'host') else 0,
            "vm_count": len(net.vm) if hasattr(net, 'vm') else 0
        }
        networks.append(network_info)
    
    # Distributed virtual switches
    dvs_networks = content.viewManager.CreateContainerView(content.rootFolder, [vim.dvs.VmwareDistributedVirtualSwitch], True)
    for dvs in dvs_networks.view:
        if net_name and dvs.name.lower() != net_name.lower():
            continue
            
        network_info = {
            "name": dvs.name,
            "type": "Distributed Virtual Switch",
            "version": dvs.config.productInfo.version if hasattr(dvs.config, 'productInfo') else None,
            "host_count": len(dvs.config.host) if hasattr(dvs.config, 'host') else 0,
            "portgroup_count": len(dvs.portgroup) if hasattr(dvs, 'portgroup') else 0
        }
        networks.append(network_info)
    
    if net_name:
        return networks[0] if networks else {"error": f"Network '{net_name}' not found", "status": "failed"}
    else:
        return {"networks": networks, "count": len(networks), "status": "success"}

async def main():
    transport = os.getenv("TRANSPORT", "stdio")
    if transport == 'sse':
        # Run the MCP server with sse transport
        await mcp.run_sse_async()
    else:
        # Run the MCP server with stdio transport
        await mcp.run_stdio_async()

if __name__ == "__main__":
    asyncio.run(main())
