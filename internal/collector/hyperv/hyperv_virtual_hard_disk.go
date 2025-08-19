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
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/prometheus-community/windows_exporter/internal/types"
	"github.com/prometheus/client_golang/prometheus"
)

// collectorVirtualHardDisk Hyper-V Virtual Hard Disk metrics
type collectorVirtualHardDisk struct {
	miSession *mi.Session

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

// WMI structures for Hyper-V Virtual Hard Disk information
type VirtualSystemSettingData struct {
	ElementName           string
	InstanceID            string
	ConfigurationName     string
	ConfigurationDataRoot string
	ConfigurationFile     string
	VirtualSystemType     string
	VirtualSystemSubType  string
	SystemName            string
	ConfigurationID       string
	Notes                 []string
}

type StorageAllocationSettingData struct {
	ElementName              string
	Parent                   string
	HostResource             []string
	InstanceID               string
	Address                  string
	AddressOnParent          string
	VirtualSystemIdentifiers []string
	ResourceType             uint16
	ResourceSubType          string
}

type VirtualHardDiskSettingData struct {
	Path               string
	Format             uint16 // 2 = VHD, 3 = VHDX
	Type               uint16 // 2 = Fixed, 3 = Dynamic, 4 = Differencing
	MaxInternalSize    uint64
	BlockSize          uint32
	LogicalSectorSize  uint32
	PhysicalSectorSize uint32
	ParentPath         string
	VirtualDiskId      string
}

type VirtualHardDiskState struct {
	Path                    string
	FileSize                uint64
	InUse                   bool
	MinimumSize             uint64
	Alignment               uint32
	FragmentationPercentage uint16
	IsPMEMCompatible        bool
}

func (c *Collector) buildVirtualHardDisk(miSession *mi.Session) error {
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

	return nil
}

func (c *Collector) collectVirtualHardDisk(ch chan<- prometheus.Metric) error {
	logger := slog.With(slog.String("collector", Name+":"+subCollectorVirtualHardDisk))
	logger.Info("=== Starting virtual hard disk collection ===")

	// Always emit this test metric to verify collector is working
	ch <- prometheus.MustNewConstMetric(
		c.vhdxCollectorInfo,
		prometheus.GaugeValue,
		1,
	)
	logger.Info("Emitted test metric")

	if c.miSession == nil {
		logger.Error("MI session not available for virtual hard disk collector")
		return fmt.Errorf("MI session not available for virtual hard disk collector")
	}
	logger.Info("MI session is available")

	// Create Hyper-V namespace
	hypervNamespace, err := mi.NewNamespace("root/virtualization/v2")
	if err != nil {
		logger.Error("Failed to create Hyper-V namespace", slog.Any("err", err))
		return fmt.Errorf("failed to create Hyper-V namespace: %w", err)
	}
	logger.Info("Created Hyper-V namespace successfully")

	// Since struct mapping isn't working, let's try using the MI Operation approach
	// similar to how other collectors work
	logger.Info("Attempting alternative MI Operation approach...")

	// Execute query and get operation
	operation, err := c.miSession.QueryInstances(mi.OperationFlagsStandardRTTI, nil, hypervNamespace, mi.QueryDialectWQL, "SELECT ElementName, InstanceID FROM Msvm_VirtualSystemSettingData WHERE VirtualSystemType = 'Microsoft:Hyper-V:System:Realized'")
	if err != nil {
		logger.Error("Failed to execute VM query operation", slog.Any("err", err))
		return fmt.Errorf("failed to execute VM query operation: %w", err)
	}
	defer operation.Close()

	vmCount := 0
	for {
		instance, result, err := operation.GetInstance()
		if err != nil {
			logger.Debug("End of VM instances", slog.Any("err", err))
			break
		}
		if instance == nil || !result {
			logger.Debug("No more VM instances")
			break
		}

		vmCount++
		logger.Info("Processing VM instance", slog.Int("vm_count", vmCount), slog.Any("result", result))

		// Try to get ElementName property
		elementNameProperty, err := instance.GetElement("ElementName")
		var vmName string
		if err == nil && elementNameProperty != nil {
			if elementNameValue, err := elementNameProperty.GetValue(); err == nil {
				if str, ok := elementNameValue.(string); ok {
					vmName = str
				}
			}
		}

		// Try to get InstanceID property
		instanceIDProperty, err := instance.GetElement("InstanceID")
		var instanceID string
		if err == nil && instanceIDProperty != nil {
			if instanceIDValue, err := instanceIDProperty.GetValue(); err == nil {
				if str, ok := instanceIDValue.(string); ok {
					instanceID = str
				}
			}
		}

		logger.Info("Retrieved VM properties",
			slog.String("vm_name", vmName),
			slog.String("instance_id", instanceID),
		)

		if vmName == "" {
			logger.Warn("VM has empty name", slog.String("instance_id", instanceID))
			continue
		}

		if instanceID == "" {
			logger.Warn("VM has empty instance ID", slog.String("vm_name", vmName))
			continue
		}

		logger.Info("=== Processing VM ===",
			slog.String("vm_name", vmName),
			slog.String("instance_id", instanceID),
		)

		// Simplified approach: Query for storage instances that contain VHD paths
		// This is much faster than the complex multi-approach method
		vhdQueryString := "SELECT HostResource, Address, AddressOnParent FROM Msvm_StorageAllocationSettingData WHERE HostResource LIKE '%.vhd%'"
		logger.Info("Querying for VHD storage instances", slog.String("query", vhdQueryString))

		vhdOperation, err := c.miSession.QueryInstances(mi.OperationFlagsStandardRTTI, nil, hypervNamespace, mi.QueryDialectWQL, vhdQueryString)
		if err != nil {
			logger.Error("Failed to execute VHD storage query",
				slog.String("vm_name", vmName),
				slog.Any("err", err),
			)
			continue
		}
		defer vhdOperation.Close()

		storageCount := 0
		for {
			storageInstance, result, err := vhdOperation.GetInstance()
			if err != nil || storageInstance == nil || !result {
				break
			}

			// Check if this storage instance belongs to our VM by checking HostResource path
			hostResourceProperty, err := storageInstance.GetElement("HostResource")
			if err != nil || hostResourceProperty == nil {
				continue
			}

			hostResourceValue, err := hostResourceProperty.GetValue()
			if err != nil {
				continue
			}

			hostResourceStr, ok := hostResourceValue.(string)
			if !ok || hostResourceStr == "" {
				continue
			}

			// Simple check: if the HostResource contains the VM's GUID, it belongs to this VM
			if strings.Contains(hostResourceStr, instanceID) || strings.Contains(hostResourceStr, strings.TrimPrefix(instanceID, "Microsoft:")) {
				storageCount++
				logger.Info("Found matching VHD storage",
					slog.String("vm_name", vmName),
					slog.Int("storage_count", storageCount),
					slog.String("host_resource", hostResourceStr),
				)

				c.processStorageInstance(ch, logger, vmName, storageInstance)
			}
		}

		logger.Info("Completed storage processing for VM",
			slog.String("vm_name", vmName),
			slog.Int("storage_instances_processed", storageCount),
		)
	}

	logger.Info("=== Completed virtual hard disk collection ===", slog.Int("total_vms_processed", vmCount))
	return nil
}

func (c *Collector) processStorageInstance(ch chan<- prometheus.Metric, logger *slog.Logger, vmName string, storageInstance *mi.Instance) {
	logger.Debug("Processing storage instance", slog.String("vm_name", vmName))

	// Quickly get HostResource as string and check if it's a VHD path
	hostResourceProperty, err := storageInstance.GetElement("HostResource")
	if err != nil || hostResourceProperty == nil {
		return
	}

	hostResourceValue, err := hostResourceProperty.GetValue()
	if err != nil {
		return
	}

	// Convert to string and check if it's a VHD path
	var vhdPath string
	if hrStr, ok := hostResourceValue.(string); ok {
		vhdPath = hrStr
	} else {
		// Skip complex array processing that was causing timeout
		return
	}

	// Quick check if this is a VHD file
	if vhdPath == "" || (!strings.HasSuffix(strings.ToLower(vhdPath), ".vhdx") && !strings.HasSuffix(strings.ToLower(vhdPath), ".vhd")) {
		return
	}

	logger.Info("Found VHD",
		slog.String("vm_name", vmName),
		slog.String("vhd_path", vhdPath),
	)

	// Simple controller info - just use defaults for now
	controllerType := "SCSI"
	controllerNumber := "0"
	controllerLocation := "0"
	vhdFilename := filepath.Base(vhdPath)

	// Emit the exists metric
	ch <- prometheus.MustNewConstMetric(
		c.vhdxExists,
		prometheus.GaugeValue,
		1, // We found it
		vmName, controllerType, controllerNumber, controllerLocation, vhdPath, vhdFilename,
	)

	logger.Info("Emitted VHD metric",
		slog.String("vm_name", vmName),
		slog.String("vhd_path", vhdPath),
	)
}

// VHDInfo combines data from multiple WMI queries
type VHDInfo struct {
	Path                    string
	Format                  uint16
	Type                    uint16
	MaxInternalSize         uint64
	BlockSize               uint32
	LogicalSectorSize       uint32
	PhysicalSectorSize      uint32
	ParentPath              string
	VirtualDiskId           string
	FileSize                uint64
	InUse                   bool
	MinimumSize             uint64
	Alignment               uint32
	FragmentationPercentage uint16
	IsPMEMCompatible        bool
}

// getVHDInfo gets VHD file properties using MI session
func (c *Collector) getVHDInfo(namespace mi.Namespace, vhdPath string) (*VHDInfo, bool) {
	logger := slog.With(slog.String("collector", Name+":"+subCollectorVirtualHardDisk))

	// Query VHD settings data
	var vhdSettings []VirtualHardDiskSettingData
	settingsQuery, err := mi.NewQuery(fmt.Sprintf("SELECT * FROM Msvm_VirtualHardDiskSettingData WHERE Path = '%s'", strings.ReplaceAll(vhdPath, `\`, `\\`)))
	if err != nil {
		logger.Debug("Failed to create VHD settings query",
			slog.String("vhd_path", vhdPath),
			slog.Any("err", err),
		)
		return nil, false
	}

	if err := c.miSession.Query(&vhdSettings, namespace, settingsQuery); err != nil {
		logger.Debug("Failed to query VHD settings",
			slog.String("vhd_path", vhdPath),
			slog.Any("err", err),
		)
		return nil, false
	}

	if len(vhdSettings) == 0 {
		logger.Debug("No VHD settings found", slog.String("vhd_path", vhdPath))
		return nil, false
	}

	logger.Debug("Found VHD settings",
		slog.String("vhd_path", vhdPath),
		slog.Int("settings_count", len(vhdSettings)),
	)

	// Initialize VHD info with settings data
	vhdInfo := &VHDInfo{
		Path:               vhdSettings[0].Path,
		Format:             vhdSettings[0].Format,
		Type:               vhdSettings[0].Type,
		MaxInternalSize:    vhdSettings[0].MaxInternalSize,
		BlockSize:          vhdSettings[0].BlockSize,
		LogicalSectorSize:  vhdSettings[0].LogicalSectorSize,
		PhysicalSectorSize: vhdSettings[0].PhysicalSectorSize,
		ParentPath:         vhdSettings[0].ParentPath,
		VirtualDiskId:      vhdSettings[0].VirtualDiskId,
		// Default values for runtime fields
		FileSize:                0,
		InUse:                   false,
		MinimumSize:             0,
		Alignment:               1,
		FragmentationPercentage: 0,
		IsPMEMCompatible:        false,
	}

	// Query Msvm_VirtualHardDiskState for additional runtime information
	var vhdStates []VirtualHardDiskState
	stateQuery, err := mi.NewQuery(fmt.Sprintf("SELECT * FROM Msvm_VirtualHardDiskState WHERE Path = '%s'", strings.ReplaceAll(vhdPath, `\`, `\\`)))
	if err == nil {
		if err := c.miSession.Query(&vhdStates, namespace, stateQuery); err == nil && len(vhdStates) > 0 {
			// Merge runtime information from state data
			state := vhdStates[0]
			vhdInfo.FileSize = state.FileSize
			vhdInfo.InUse = state.InUse
			vhdInfo.MinimumSize = state.MinimumSize
			vhdInfo.Alignment = state.Alignment
			vhdInfo.FragmentationPercentage = state.FragmentationPercentage
			vhdInfo.IsPMEMCompatible = state.IsPMEMCompatible

			logger.Debug("Merged VHD state data",
				slog.String("vhd_path", vhdPath),
				slog.Uint64("file_size", state.FileSize),
				slog.Bool("in_use", state.InUse),
			)
		} else {
			logger.Debug("Failed to query VHD state or no state found",
				slog.String("vhd_path", vhdPath),
				slog.Any("err", err),
			)
		}
	} else {
		logger.Debug("Failed to create VHD state query",
			slog.String("vhd_path", vhdPath),
			slog.Any("err", err),
		)
	}

	return vhdInfo, true
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
