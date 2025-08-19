# hyperv_virtual_hard_disk collector

The hyperv_virtual_hard_disk collector exposes metrics about virtual hard disks (VHD/VHDX) attached to Hyper-V virtual machines.

|||
-|-
Metric name prefix  | `windows_hyperv`
Data source         | Hyper-V WMI classes: `Msvm_VirtualSystemSettingData`, `Msvm_StorageAllocationSettingData`, `Msvm_VirtualHardDiskSettingData`, `Msvm_VirtualHardDiskState` (via Management Infrastructure)
Counters            | Virtual hard disk properties, configuration, and runtime state
Enabled by default? | Yes

## Flags

None

## Metrics

Name | Description | Type | Labels
-----|-------------|------|-------
`windows_hyperv_vhd_exists` | Whether the virtual hard disk exists (1 = exists, 0 = missing) | gauge | `vm_name`, `controller_type`, `controller_number`, `controller_location`, `vhd_path`, `vhd_filename`
`windows_hyperv_vhd_controller_number` | Controller number for the virtual hard disk | gauge | `vm_name`, `controller_type`, `vhd_path`, `vhd_filename`
`windows_hyperv_vhd_controller_location` | Controller location for the virtual hard disk | gauge | `vm_name`, `controller_type`, `vhd_path`, `vhd_filename`
`windows_hyperv_vhd_file_size_bytes` | Current file size of the virtual hard disk in bytes | gauge | `vm_name`, `controller_type`, `vhd_path`, `vhd_filename`, `vhd_format`, `vhd_type`
`windows_hyperv_vhd_size_bytes` | Maximum size of the virtual hard disk in bytes | gauge | `vm_name`, `controller_type`, `vhd_path`, `vhd_filename`, `vhd_format`, `vhd_type`
`windows_hyperv_vhd_minimum_size_bytes` | Minimum size of the virtual hard disk in bytes | gauge | `vm_name`, `controller_type`, `vhd_path`, `vhd_filename`, `vhd_format`, `vhd_type`
`windows_hyperv_vhd_logical_sector_size_bytes` | Logical sector size of the virtual hard disk in bytes | gauge | `vm_name`, `controller_type`, `vhd_path`, `vhd_filename`, `vhd_format`, `vhd_type`
`windows_hyperv_vhd_physical_sector_size_bytes` | Physical sector size of the virtual hard disk in bytes | gauge | `vm_name`, `controller_type`, `vhd_path`, `vhd_filename`, `vhd_format`, `vhd_type`
`windows_hyperv_vhd_block_size_bytes` | Block size of the virtual hard disk in bytes | gauge | `vm_name`, `controller_type`, `vhd_path`, `vhd_filename`, `vhd_format`, `vhd_type`
`windows_hyperv_vhd_fragmentation_percentage` | Fragmentation percentage of the virtual hard disk | gauge | `vm_name`, `controller_type`, `vhd_path`, `vhd_filename`, `vhd_format`, `vhd_type`
`windows_hyperv_vhd_alignment` | Alignment of the virtual hard disk | gauge | `vm_name`, `controller_type`, `vhd_path`, `vhd_filename`, `vhd_format`, `vhd_type`
`windows_hyperv_vhd_attached` | Whether the virtual hard disk is attached (1 = attached, 0 = not attached) | gauge | `vm_name`, `controller_type`, `vhd_path`, `vhd_filename`, `vhd_format`, `vhd_type`
`windows_hyperv_vhd_is_pmem_compatible` | Whether the virtual hard disk is PMEM compatible (1 = compatible, 0 = not compatible) | gauge | `vm_name`, `controller_type`, `vhd_path`, `vhd_filename`, `vhd_format`, `vhd_type`

### Labels

Label | Description | Values
------|-------------|-------
`vm_name` | Name of the virtual machine | 
`controller_type` | Type of storage controller | `SCSI`, `IDE`, `Unknown`
`controller_number` | Controller number (as string) |
`controller_location` | Location on the controller (as string) |
`vhd_path` | Full path to the VHD/VHDX file |
`vhd_filename` | Filename of the VHD/VHDX file |
`vhd_format` | Virtual hard disk format | `VHD`, `VHDX`, `Unknown`
`vhd_type` | Virtual hard disk type | `Fixed`, `Dynamic`, `Differencing`, `Unknown`

## Notes

This collector provides information equivalent to the PowerShell commands:
- `Get-VMHardDiskDrive` - for VM to VHD mapping and controller information
- `Get-VHD` - for detailed VHD properties and statistics

The collector queries multiple Hyper-V WMI classes via the Management Infrastructure (MI) API:
- `Msvm_VirtualSystemSettingData` - for virtual machine information
- `Msvm_StorageAllocationSettingData` - for storage device mappings  
- `Msvm_VirtualHardDiskSettingData` - for VHD configuration and properties
- `Msvm_VirtualHardDiskState` - for VHD runtime state and statistics

Runtime metrics such as current file size, fragmentation percentage, and usage status are obtained from `Msvm_VirtualHardDiskState`, while configuration properties like maximum size, format, and type come from `Msvm_VirtualHardDiskSettingData`.

## Example Output

```
# HELP windows_hyperv_vhd_file_size_bytes Current file size of the virtual hard disk in bytes
# TYPE windows_hyperv_vhd_file_size_bytes gauge
windows_hyperv_vhd_file_size_bytes{controller_type="SCSI",vhd_filename="windows-11-23h2.vhdx",vhd_format="VHDX",vhd_path="C:\\VMs\\Test-VM-1\\windows-11-23h2.vhdx",vhd_type="Dynamic",vm_name="Test-VM-1"} 3.5605446656e+10

# HELP windows_hyperv_vhd_size_bytes Maximum size of the virtual hard disk in bytes  
# TYPE windows_hyperv_vhd_size_bytes gauge
windows_hyperv_vhd_size_bytes{controller_type="SCSI",vhd_filename="windows-11-23h2.vhdx",vhd_format="VHDX",vhd_path="C:\\VMs\\Test-VM-1\\windows-11-23h2.vhdx",vhd_type="Dynamic",vm_name="Test-VM-1"} 6.442450944e+10

# HELP windows_hyperv_vhd_fragmentation_percentage Fragmentation percentage of the virtual hard disk
# TYPE windows_hyperv_vhd_fragmentation_percentage gauge
windows_hyperv_vhd_fragmentation_percentage{controller_type="SCSI",vhd_filename="windows-11-23h2.vhdx",vhd_format="VHDX",vhd_path="C:\\VMs\\Test-VM-1\\windows-11-23h2.vhdx",vhd_type="Dynamic",vm_name="Test-VM-1"} 9
```
