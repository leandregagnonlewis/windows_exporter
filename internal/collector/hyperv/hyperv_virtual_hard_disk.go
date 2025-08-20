// SPDX-License-Identifier: Apache-2.0
//
// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package hyperv

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/prometheus-community/windows_exporter/internal/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"
)

// collectorVirtualHardDisk Hyper-V Virtual Hard Disk metrics
type collectorVirtualHardDisk struct {
	miSession *mi.Session

	// MI queries
	vmQuery      mi.Query
	storageQuery string

	// Test metric
	vhdxCollectorInfo *prometheus.Desc

	// Virtual Hard Disk metrics
	vhdxExists                  *prometheus.Desc
	vhdxControllerNumber        *prometheus.Desc
	vhdxControllerLocation      *prometheus.Desc
	vhdxFileSize                *prometheus.Desc
	vhdxSize                    *prometheus.Desc
	vhdxMinimumSize             *prometheus.Desc
	vhdxLogicalSectorSize       *prometheus.Desc
	vhdxPhysicalSectorSize      *prometheus.Desc
	vhdxBlockSize               *prometheus.Desc
	vhdxFragmentationPercentage *prometheus.Desc
	vhdxAlignment               *prometheus.Desc
	vhdxAttached                *prometheus.Desc
	vhdxIsPMEMCompatible        *prometheus.Desc
}

// MI structures for WMI data mapping - following cpu_info.go pattern
type miVirtualSystemSettingData struct {
	ElementName       string `mi:"ElementName"`
	InstanceID        string `mi:"InstanceID"`
	VirtualSystemType string `mi:"VirtualSystemType"`
}

type miStorageAllocationSettingData struct {
	ElementName     string   `mi:"ElementName"`
	InstanceID      string   `mi:"InstanceID"`
	HostResource    []string `mi:"HostResource"`
	Address         string   `mi:"Address"`
	AddressOnParent string   `mi:"AddressOnParent"`
	ResourceType    uint16   `mi:"ResourceType"`
	ResourceSubType string   `mi:"ResourceSubType"`
}

type miVirtualHardDiskSettingData struct {
	Path               string `mi:"Path"`
	Format             uint16 `mi:"Format"` // 2 = VHD, 3 = VHDX
	Type               uint16 `mi:"Type"`   // 2 = Fixed, 3 = Dynamic, 4 = Differencing
	MaxInternalSize    uint64 `mi:"MaxInternalSize"`
	BlockSize          uint32 `mi:"BlockSize"`
	LogicalSectorSize  uint32 `mi:"LogicalSectorSize"`
	PhysicalSectorSize uint32 `mi:"PhysicalSectorSize"`
	ParentPath         string `mi:"ParentPath"`
	VirtualDiskId      string `mi:"VirtualDiskId"`
}

type miVirtualHardDiskState struct {
	Path                    string `mi:"Path"`
	FileSize                uint64 `mi:"FileSize"`
	InUse                   bool   `mi:"InUse"`
	MinimumSize             uint64 `mi:"MinimumSize"`
	Alignment               uint32 `mi:"Alignment"`
	FragmentationPercentage uint16 `mi:"FragmentationPercentage"`
	IsPMEMCompatible        bool   `mi:"IsPMEMCompatible"`
}

// VHDInfo contains information about a VHD file extracted using file system and volume APIs
type VHDInfo struct {
	Path                    string
	VirtualSize             uint64
	PhysicalSize            uint64
	BlockSize               uint32
	LogicalSectorSize       uint32
	PhysicalSectorSize      uint32
	VHDType                 string
	VHDFormat               string
	FragmentationPercentage uint16
	VolumeInfo              volumeInfo
}

// volumeInfo mirrors the logical_disk collector's volumeInfo struct
type volumeInfo struct {
	diskIDs      string
	filesystem   string
	serialNumber string
	label        string
	volumeType   string
	readonly     float64
}

func (c *Collector) buildVirtualHardDisk(miSession *mi.Session) error {
	if miSession == nil {
		return fmt.Errorf("miSession is nil")
	}

	// Store the MI session for use in collection
	c.miSession = miSession

	// Test metric to verify collector is working
	c.vhdxCollectorInfo = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_collector_info"),
		"Information about the VHD collector (always 1 when active)",
		[]string{},
		nil,
	)

	// Virtual Hard Disk metrics
	c.vhdxExists = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_exists"),
		"Whether the virtual hard disk exists (1 = exists, 0 = missing)",
		[]string{"vm_name", "controller_type", "controller_number", "controller_location", "vhd_path", "vhd_filename"},
		nil,
	)

	c.vhdxControllerNumber = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_controller_number"),
		"Controller number for the virtual hard disk",
		[]string{"vm_name", "controller_type", "vhd_path", "vhd_filename"},
		nil,
	)

	c.vhdxControllerLocation = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_controller_location"),
		"Controller location for the virtual hard disk",
		[]string{"vm_name", "controller_type", "vhd_path", "vhd_filename"},
		nil,
	)

	c.vhdxFileSize = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_file_size_bytes"),
		"Current file size of the virtual hard disk in bytes",
		[]string{"vm_name", "controller_type", "vhd_path", "vhd_filename", "vhd_format", "vhd_type"},
		nil,
	)

	c.vhdxSize = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_size_bytes"),
		"Maximum size of the virtual hard disk in bytes",
		[]string{"vm_name", "controller_type", "vhd_path", "vhd_filename", "vhd_format", "vhd_type"},
		nil,
	)

	c.vhdxMinimumSize = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_minimum_size_bytes"),
		"Minimum size of the virtual hard disk in bytes",
		[]string{"vm_name", "controller_type", "vhd_path", "vhd_filename", "vhd_format", "vhd_type"},
		nil,
	)

	c.vhdxLogicalSectorSize = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_logical_sector_size_bytes"),
		"Logical sector size of the virtual hard disk in bytes",
		[]string{"vm_name", "controller_type", "vhd_path", "vhd_filename", "vhd_format", "vhd_type"},
		nil,
	)

	c.vhdxPhysicalSectorSize = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_physical_sector_size_bytes"),
		"Physical sector size of the virtual hard disk in bytes",
		[]string{"vm_name", "controller_type", "vhd_path", "vhd_filename", "vhd_format", "vhd_type"},
		nil,
	)

	c.vhdxBlockSize = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_block_size_bytes"),
		"Block size of the virtual hard disk in bytes",
		[]string{"vm_name", "controller_type", "vhd_path", "vhd_filename", "vhd_format", "vhd_type"},
		nil,
	)

	c.vhdxFragmentationPercentage = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_fragmentation_percentage"),
		"Fragmentation percentage of the virtual hard disk",
		[]string{"vm_name", "controller_type", "vhd_path", "vhd_filename", "vhd_format", "vhd_type"},
		nil,
	)

	c.vhdxAlignment = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_alignment"),
		"Alignment of the virtual hard disk",
		[]string{"vm_name", "controller_type", "vhd_path", "vhd_filename", "vhd_format", "vhd_type"},
		nil,
	)

	c.vhdxAttached = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_attached"),
		"Whether the virtual hard disk is attached (1 = attached, 0 = not attached)",
		[]string{"vm_name", "controller_type", "vhd_path", "vhd_filename", "vhd_format", "vhd_type"},
		nil,
	)

	c.vhdxIsPMEMCompatible = prometheus.NewDesc(
		prometheus.BuildFQName(types.Namespace, Name, "vhd_is_pmem_compatible"),
		"Whether the virtual hard disk is PMEM compatible (1 = compatible, 0 = not compatible)",
		[]string{"vm_name", "controller_type", "vhd_path", "vhd_filename", "vhd_format", "vhd_type"},
		nil,
	)

	// Create MI queries following cpu_info.go pattern
	vmQuery, err := mi.NewQuery("SELECT ElementName, InstanceID FROM Msvm_VirtualSystemSettingData WHERE VirtualSystemType = 'Microsoft:Hyper-V:System:Realized'")
	if err != nil {
		return fmt.Errorf("failed to create VM query: %w", err)
	}
	c.vmQuery = vmQuery

	// Create storage query string for WMI namespace queries
	var testStorage []miStorageAllocationSettingData
	c.storageQuery = wmi.CreateQuery(&testStorage, "WHERE Parent IS NOT NULL", "Msvm_StorageAllocationSettingData")

	// Test the queries to make sure they work - following cpu_info.go pattern
	hypervNamespace, err := mi.NewNamespace("root/virtualization/v2")
	if err != nil {
		return fmt.Errorf("failed to create Hyper-V namespace: %w", err)
	}

	var testVMs []miVirtualSystemSettingData
	if err := c.miSession.Query(&testVMs, hypervNamespace, c.vmQuery); err != nil {
		return fmt.Errorf("VM WMI query failed: %w", err)
	}

	if err := wmi.QueryNamespace(c.storageQuery, &testStorage, "root/virtualization/v2"); err != nil {
		return fmt.Errorf("Storage WMI query failed: %w", err)
	}

	return nil
}

func (c *Collector) collectVirtualHardDisk(ch chan<- prometheus.Metric) error {
	logger := slog.With(slog.String("collector", Name+":"+subCollectorVirtualHardDisk))

	// Always emit test metric
	ch <- prometheus.MustNewConstMetric(
		c.vhdxCollectorInfo,
		prometheus.GaugeValue,
		1,
	)

	// Create Hyper-V namespace
	hypervNamespace, err := mi.NewNamespace("root/virtualization/v2")
	if err != nil {
		logger.Error("Failed to create Hyper-V namespace", slog.Any("err", err))
		return fmt.Errorf("failed to create Hyper-V namespace: %w", err)
	}

	// Query VMs using the prepared query - following cpu_info.go pattern
	var vms []miVirtualSystemSettingData
	if err := c.miSession.Query(&vms, hypervNamespace, c.vmQuery); err != nil {
		logger.Error("VM WMI query failed", slog.Any("err", err))
		return fmt.Errorf("VM WMI query failed: %w", err)
	}

	logger.Info("Found VMs", slog.Int("vm_count", len(vms)))

	// Query storage allocation data using WMI namespace query
	var storageData []miStorageAllocationSettingData
	if err := wmi.QueryNamespace(c.storageQuery, &storageData, "root/virtualization/v2"); err != nil {
		logger.Error("Storage WMI query failed", slog.Any("err", err))
		return fmt.Errorf("Storage WMI query failed: %w", err)
	}

	logger.Info("Found storage instances", slog.Int("storage_count", len(storageData)))

	// Build a map of VM InstanceID to VM Name for efficient lookup
	vmMap := make(map[string]string)
	for _, vm := range vms {
		vmMap[vm.InstanceID] = vm.ElementName
		logger.Debug("VM mapping",
			slog.String("instance_id", vm.InstanceID),
			slog.String("vm_name", vm.ElementName),
		)
	}

	// Process each storage instance
	for _, storage := range storageData {
		// Skip storage instances that don't have VHD files
		hasVHD := false
		for _, hostResource := range storage.HostResource {
			if hostResource != "" &&
				(strings.HasSuffix(strings.ToLower(hostResource), ".vhdx") ||
					strings.HasSuffix(strings.ToLower(hostResource), ".vhd")) {
				hasVHD = true
				break
			}
		}

		if !hasVHD {
			continue
		}

		// Find which VM this storage belongs to
		var vmName string
		var vmInstanceID string

		for instanceID, name := range vmMap {
			// Check if the storage InstanceID contains the VM's GUID
			if strings.Contains(storage.InstanceID, instanceID) ||
				strings.Contains(storage.InstanceID, strings.TrimPrefix(instanceID, "Microsoft:")) {
				vmName = name
				vmInstanceID = instanceID
				break
			}
		}

		if vmName == "" {
			logger.Debug("Could not match storage to VM",
				slog.String("storage_instance_id", storage.InstanceID),
			)
			continue
		}

		// Process each HostResource (VHD path)
		for _, hostResource := range storage.HostResource {
			// Check if this is a VHD file
			if hostResource == "" ||
				(!strings.HasSuffix(strings.ToLower(hostResource), ".vhdx") &&
					!strings.HasSuffix(strings.ToLower(hostResource), ".vhd")) {
				continue
			}

			logger.Info("Found VHD",
				slog.String("vm_name", vmName),
				slog.String("vm_instance_id", vmInstanceID),
				slog.String("vhd_path", hostResource),
			)

			// Parse controller information
			controllerType, controllerNumber, controllerLocation := c.parseControllerInfo(storage.Address, storage.AddressOnParent)
			vhdFilename := filepath.Base(hostResource)

			// Query for detailed VHD information
			vhdInfo, err := c.getVHDDetails(hostResource, logger)
			if err != nil {
				logger.Debug("Failed to get VHD details",
					slog.String("vhd_path", hostResource),
					slog.Any("err", err))
				// Continue with limited information
			}

			// Emit the exists metric
			ch <- prometheus.MustNewConstMetric(
				c.vhdxExists,
				prometheus.GaugeValue,
				1, // We found it
				vmName, controllerType, controllerNumber, controllerLocation, hostResource, vhdFilename,
			)

			// Emit controller metrics
			ch <- prometheus.MustNewConstMetric(
				c.vhdxControllerNumber,
				prometheus.GaugeValue,
				parseStringToFloat(controllerNumber),
				vmName, controllerType, hostResource, vhdFilename,
			)

			ch <- prometheus.MustNewConstMetric(
				c.vhdxControllerLocation,
				prometheus.GaugeValue,
				parseStringToFloat(controllerLocation),
				vmName, controllerType, hostResource, vhdFilename,
			)

			// Emit detailed VHD metrics if we have the data
			vhdFormat := "Unknown"
			vhdType := "Unknown"

			if vhdInfo != nil {
				vhdFormat = vhdInfo.VHDFormat
				vhdType = vhdInfo.VHDType

				ch <- prometheus.MustNewConstMetric(
					c.vhdxSize,
					prometheus.GaugeValue,
					float64(vhdInfo.VirtualSize),
					vmName, controllerType, hostResource, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxLogicalSectorSize,
					prometheus.GaugeValue,
					float64(vhdInfo.LogicalSectorSize),
					vmName, controllerType, hostResource, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxPhysicalSectorSize,
					prometheus.GaugeValue,
					float64(vhdInfo.PhysicalSectorSize),
					vmName, controllerType, hostResource, vhdFilename, vhdFormat, vhdType,
				)

				if vhdInfo.BlockSize > 0 {
					ch <- prometheus.MustNewConstMetric(
						c.vhdxBlockSize,
						prometheus.GaugeValue,
						float64(vhdInfo.BlockSize),
						vmName, controllerType, hostResource, vhdFilename, vhdFormat, vhdType,
					)
				}

				ch <- prometheus.MustNewConstMetric(
					c.vhdxFileSize,
					prometheus.GaugeValue,
					float64(vhdInfo.PhysicalSize),
					vmName, controllerType, hostResource, vhdFilename, vhdFormat, vhdType,
				)

				// Use default values for metrics not available from file system APIs
				ch <- prometheus.MustNewConstMetric(
					c.vhdxMinimumSize,
					prometheus.GaugeValue,
					0, // Not available without VHD parsing
					vmName, controllerType, hostResource, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxAlignment,
					prometheus.GaugeValue,
					0, // Not available without VHD parsing
					vmName, controllerType, hostResource, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxFragmentationPercentage,
					prometheus.GaugeValue,
					float64(vhdInfo.FragmentationPercentage),
					vmName, controllerType, hostResource, vhdFilename, vhdFormat, vhdType,
				)

				// Use default values for boolean metrics not available from file system APIs
				ch <- prometheus.MustNewConstMetric(
					c.vhdxAttached,
					prometheus.GaugeValue,
					0, // Not available without VHD parsing
					vmName, controllerType, hostResource, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxIsPMEMCompatible,
					prometheus.GaugeValue,
					0, // Not available without VHD parsing
					vmName, controllerType, hostResource, vhdFilename, vhdFormat, vhdType,
				)

				// Log volume information for debugging
				logger.Debug("VHD volume information",
					slog.String("vm_name", vmName),
					slog.String("vhd_path", hostResource),
					slog.String("filesystem", vhdInfo.VolumeInfo.filesystem),
					slog.String("volume_type", vhdInfo.VolumeInfo.volumeType),
					slog.String("disk_ids", vhdInfo.VolumeInfo.diskIDs),
				)
			}

			logger.Debug("Emitted VHD metric",
				slog.String("vm_name", vmName),
				slog.String("vhd_path", hostResource),
			)
		}
	}

	logger.Info("Completed VHD collection",
		slog.Int("vm_count", len(vms)),
		slog.Int("storage_count", len(storageData)),
	)

	return nil
}

// parseControllerInfo extracts controller type, number, and location from WMI data
func (c *Collector) parseControllerInfo(address, addressOnParent string) (controllerType, controllerNumber, controllerLocation string) {
	// Default values
	controllerType = "Unknown"
	controllerNumber = "0"
	controllerLocation = "0"

	// Parse the address to determine controller type and numbers
	// Address format varies but typically:
	// - IDE controllers use simple numeric addresses
	// - SCSI controllers use different format
	if address != "" {
		if len(address) <= 2 {
			// Likely IDE controller
			controllerType = "IDE"
			controllerNumber = "0"
			controllerLocation = address
		} else {
			// Likely SCSI controller
			controllerType = "SCSI"
			controllerNumber = "0"
			controllerLocation = address
		}
	}

	if addressOnParent != "" {
		controllerLocation = addressOnParent
	}

	return controllerType, controllerNumber, controllerLocation
}

// getVHDFormat converts format number to string
func getVHDFormat(format uint16) string {
	switch format {
	case 2:
		return "VHD"
	case 3:
		return "VHDX"
	default:
		return "Unknown"
	}
}

// getVHDType converts type number to string
func getVHDType(vhdType uint16) string {
	switch vhdType {
	case 2:
		return "Fixed"
	case 3:
		return "Dynamic"
	case 4:
		return "Differencing"
	default:
		return "Unknown"
	}
}

// getVHDDetails gets VHD information using file system APIs and volume information
func (c *Collector) getVHDDetails(vhdPath string, logger *slog.Logger) (*VHDInfo, error) {
	// Get file information
	fileInfo, err := os.Stat(vhdPath)
	if err != nil {
		logger.Debug("Failed to get VHD file information",
			slog.String("vhd_path", vhdPath),
			slog.Any("err", err))
		return nil, fmt.Errorf("failed to get VHD file information: %w", err)
	}

	// Determine VHD format from file extension
	vhdFormat := "VHD"
	if strings.HasSuffix(strings.ToLower(vhdPath), ".vhdx") {
		vhdFormat = "VHDX"
	}

	// Extract drive letter from VHD path for volume information
	driveLetter := filepath.VolumeName(vhdPath)
	if driveLetter == "" {
		// Fallback: try to extract drive letter manually
		if len(vhdPath) >= 2 && vhdPath[1] == ':' {
			driveLetter = vhdPath[:2]
		}
	}

	// Get volume information for the drive containing the VHD
	var volInfo volumeInfo
	if driveLetter != "" {
		volumes, err := getAllMountedVolumes()
		if err != nil {
			logger.Debug("Failed to get mounted volumes",
				slog.String("vhd_path", vhdPath),
				slog.Any("err", err))
		} else {
			volInfo, err = getVolumeInfo(volumes, driveLetter)
			if err != nil {
				logger.Debug("Failed to get volume information",
					slog.String("drive", driveLetter),
					slog.Any("err", err))
				// Continue with empty volume info
			}
		}
	}

	// Create VHD info structure with available information
	vhdInfo := &VHDInfo{
		Path:                    vhdPath,
		VHDFormat:               vhdFormat,
		VHDType:                 "Unknown", // Can't determine without opening VHD
		PhysicalSize:            uint64(fileInfo.Size()),
		VirtualSize:             uint64(fileInfo.Size()), // Default to physical size
		LogicalSectorSize:       512,                     // Standard default
		PhysicalSectorSize:      512,                     // Standard default
		BlockSize:               0,                       // Not available without VHD parsing
		FragmentationPercentage: 100,                     // Conservative default (fully allocated)
		VolumeInfo:              volInfo,
	}

	return vhdInfo, nil
}

// getAllMountedVolumes returns a map of mounted volumes (adapted from logical_disk collector)
func getAllMountedVolumes() (map[string]string, error) {
	guidBuf := make([]uint16, windows.MAX_PATH+1)
	guidBufLen := uint32(len(guidBuf) * 2)

	hFindVolume, err := windows.FindFirstVolume(&guidBuf[0], guidBufLen)
	if err != nil {
		return nil, fmt.Errorf("FindFirstVolume: %w", err)
	}

	defer func() {
		_ = windows.FindVolumeClose(hFindVolume)
	}()

	volumes := map[string]string{}

	for ; ; err = windows.FindNextVolume(hFindVolume, &guidBuf[0], guidBufLen) {
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				return volumes, nil
			}
			return nil, fmt.Errorf("FindNextVolume: %w", err)
		}

		var rootPathLen uint32
		rootPathBuf := make([]uint16, windows.MAX_PATH+1)
		rootPathBufLen := uint32(len(rootPathBuf) * 2)

		for {
			err = windows.GetVolumePathNamesForVolumeName(&guidBuf[0], &rootPathBuf[0], rootPathBufLen, &rootPathLen)
			if err == nil {
				break
			}

			if err == windows.ERROR_FILE_NOT_FOUND {
				// the volume is not mounted
				break
			}

			if err == windows.ERROR_MORE_DATA {
				rootPathBuf = make([]uint16, (rootPathLen+1)/2)
				continue
			}

			return nil, fmt.Errorf("GetVolumePathNamesForVolumeName: %w", err)
		}

		mountPoint := windows.UTF16ToString(rootPathBuf)

		// Skip unmounted volumes
		if len(mountPoint) == 0 {
			continue
		}

		volumes[strings.TrimSuffix(mountPoint, `\`)] = strings.TrimSuffix(windows.UTF16ToString(guidBuf), `\`)
	}
}

// getVolumeInfo returns volume information for a given drive (adapted from logical_disk collector)
func getVolumeInfo(volumes map[string]string, rootDrive string) (volumeInfo, error) {
	volumePath := rootDrive

	// If rootDrive is a NTFS directory, convert it to a volume GUID.
	if volumeGUID, ok := volumes[rootDrive]; ok {
		volumePath, _ = strings.CutPrefix(volumeGUID, `\\?\`)
	}

	volumePathPtr := windows.StringToUTF16Ptr(`\\.\` + volumePath)

	// mode has to include FILE_SHARE permission to allow concurrent access to the disk.
	// use 0 as access mode to avoid admin permission.
	mode := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	attr := uint32(windows.FILE_ATTRIBUTE_READONLY)

	volumeHandle, err := windows.CreateFile(volumePathPtr, 0, mode, nil, windows.OPEN_EXISTING, attr, 0)
	if err != nil {
		return volumeInfo{}, fmt.Errorf("could not open volume for %s: %w", rootDrive, err)
	}

	defer func(fd windows.Handle) {
		_ = windows.Close(fd)
	}(volumeHandle)

	controlCode := uint32(5636096) // IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
	volumeDiskExtents := make([]byte, 16*1024)

	var bytesReturned uint32

	err = windows.DeviceIoControl(volumeHandle, controlCode, nil, 0, &volumeDiskExtents[0], uint32(len(volumeDiskExtents)), &bytesReturned, nil)
	if err != nil {
		return volumeInfo{}, fmt.Errorf("could not identify physical drive for %s: %w", rootDrive, err)
	}

	numDiskIDs := uint(binary.LittleEndian.Uint32(volumeDiskExtents))
	if numDiskIDs < 1 {
		return volumeInfo{}, fmt.Errorf("could not identify physical drive for %s: no disk IDs returned", rootDrive)
	}

	diskIDs := make([]string, numDiskIDs)

	// diskExtentSize Size of the DiskExtent structure in bytes.
	const diskExtentSize = 24

	for i := range numDiskIDs {
		diskIDs[i] = strconv.FormatUint(uint64(binary.LittleEndian.Uint32(volumeDiskExtents[8+i*diskExtentSize:])), 10)
	}

	slices.Sort(diskIDs)
	diskIDs = slices.Compact(diskIDs)

	volumeInformationRootDrive := volumePath + `\`

	if strings.Contains(volumePath, `Volume`) {
		volumeInformationRootDrive = `\\?\` + volumeInformationRootDrive
	}

	volumeInformationRootDrivePtr := windows.StringToUTF16Ptr(volumeInformationRootDrive)
	driveType := windows.GetDriveType(volumeInformationRootDrivePtr)
	volBufLabel := make([]uint16, windows.MAX_PATH+1)
	volSerialNum := uint32(0)
	fsFlags := uint32(0)
	volBufType := make([]uint16, windows.MAX_PATH+1)

	err = windows.GetVolumeInformation(
		volumeInformationRootDrivePtr,
		&volBufLabel[0], uint32(len(volBufLabel)),
		&volSerialNum, nil, &fsFlags,
		&volBufType[0], uint32(len(volBufType)),
	)
	if err != nil {
		if driveType == windows.DRIVE_CDROM || driveType == windows.DRIVE_REMOVABLE {
			return volumeInfo{}, nil
		}

		return volumeInfo{}, fmt.Errorf("could not get volume information for %s: %w", volumeInformationRootDrive, err)
	}

	return volumeInfo{
		diskIDs:      strings.Join(diskIDs, ";"),
		volumeType:   getDriveType(driveType),
		label:        windows.UTF16PtrToString(&volBufLabel[0]),
		filesystem:   windows.UTF16PtrToString(&volBufType[0]),
		serialNumber: fmt.Sprintf("%X", volSerialNum),
		readonly:     float64(fsFlags & windows.FILE_READ_ONLY_VOLUME),
	}, nil
}

// getDriveType converts Windows drive type to string (adapted from logical_disk collector)
func getDriveType(driveType uint32) string {
	switch driveType {
	case windows.DRIVE_UNKNOWN:
		return "unknown"
	case windows.DRIVE_NO_ROOT_DIR:
		return "norootdir"
	case windows.DRIVE_REMOVABLE:
		return "removable"
	case windows.DRIVE_FIXED:
		return "fixed"
	case windows.DRIVE_REMOTE:
		return "remote"
	case windows.DRIVE_CDROM:
		return "cdrom"
	case windows.DRIVE_RAMDISK:
		return "ramdisk"
	default:
		return "unknown"
	}
}

// Helper functions
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func parseStringToFloat(s string) float64 {
	if s == "" {
		return 0
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return f
}
