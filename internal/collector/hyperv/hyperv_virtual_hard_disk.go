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
	ElementName string
	InstanceID  string
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

	if c.miSession == nil {
		logger.Debug("MI session not available for virtual hard disk collector")
		return nil
	}

	// Query for all VMs using root\virtualization\v2 namespace
	var vms []VirtualSystemSettingData
	vmQuery, err := mi.NewQuery("SELECT ElementName, InstanceID FROM Msvm_VirtualSystemSettingData WHERE VirtualSystemType = 'Microsoft:Hyper-V:System:Realized'")
	if err != nil {
		return fmt.Errorf("failed to create VM query: %w", err)
	}

	// Create Hyper-V namespace
	hypervNamespace, err := mi.NewNamespace("root/virtualization/v2")
	if err != nil {
		return fmt.Errorf("failed to create Hyper-V namespace: %w", err)
	}

	if err := c.miSession.Query(&vms, hypervNamespace, vmQuery); err != nil {
		logger.Debug("Failed to query VMs - Hyper-V may not be available",
			slog.Any("err", err),
		)
		return nil // Don't error out if Hyper-V is not available
	}

	for _, vm := range vms {
		vmName := vm.ElementName
		if vmName == "" {
			continue
		}

		// Query storage allocation settings for this VM
		var storageSettings []StorageAllocationSettingData
		storageQuery, err := mi.NewQuery(fmt.Sprintf("SELECT * FROM Msvm_StorageAllocationSettingData WHERE InstanceID LIKE '%%%s%%'", vm.InstanceID))
		if err != nil {
			logger.Debug("Failed to create storage query for VM",
				slog.String("vm_name", vmName),
				slog.Any("err", err),
			)
			continue
		}

		if err := c.miSession.Query(&storageSettings, hypervNamespace, storageQuery); err != nil {
			logger.Debug("Failed to query storage settings for VM",
				slog.String("vm_name", vmName),
				slog.Any("err", err),
			)
			continue
		}

		for _, storage := range storageSettings {
			if len(storage.HostResource) == 0 {
				continue
			}

			vhdPath := storage.HostResource[0]
			if vhdPath == "" || (!strings.HasSuffix(strings.ToLower(vhdPath), ".vhdx") && !strings.HasSuffix(strings.ToLower(vhdPath), ".vhd")) {
				continue
			}

			// Parse controller information from Address
			controllerType, controllerNumber, controllerLocation := c.parseControllerInfo(storage.Address, storage.AddressOnParent)

			vhdFilename := filepath.Base(vhdPath)

			// Get VHD properties using MI session
			vhdInfo, exists := c.getVHDInfo(hypervNamespace, vhdPath)

			ch <- prometheus.MustNewConstMetric(
				c.vhdxExists,
				prometheus.GaugeValue,
				float64(boolToInt(exists)),
				vmName, controllerType, controllerNumber, controllerLocation, vhdPath, vhdFilename,
			)

			if exists && vhdInfo != nil {
				vhdFormat := getVHDFormat(vhdInfo.Format)
				vhdType := getVHDType(vhdInfo.Type)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxControllerNumber,
					prometheus.GaugeValue,
					parseStringToFloat(controllerNumber),
					vmName, controllerType, vhdPath, vhdFilename,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxControllerLocation,
					prometheus.GaugeValue,
					parseStringToFloat(controllerLocation),
					vmName, controllerType, vhdPath, vhdFilename,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxFileSize,
					prometheus.GaugeValue,
					float64(vhdInfo.FileSize),
					vmName, controllerType, vhdPath, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxSize,
					prometheus.GaugeValue,
					float64(vhdInfo.MaxInternalSize),
					vmName, controllerType, vhdPath, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxMinimumSize,
					prometheus.GaugeValue,
					float64(vhdInfo.MinimumSize),
					vmName, controllerType, vhdPath, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxLogicalSectorSize,
					prometheus.GaugeValue,
					float64(vhdInfo.LogicalSectorSize),
					vmName, controllerType, vhdPath, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxPhysicalSectorSize,
					prometheus.GaugeValue,
					float64(vhdInfo.PhysicalSectorSize),
					vmName, controllerType, vhdPath, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxBlockSize,
					prometheus.GaugeValue,
					float64(vhdInfo.BlockSize),
					vmName, controllerType, vhdPath, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxFragmentationPercentage,
					prometheus.GaugeValue,
					float64(vhdInfo.FragmentationPercentage),
					vmName, controllerType, vhdPath, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxAlignment,
					prometheus.GaugeValue,
					float64(vhdInfo.Alignment),
					vmName, controllerType, vhdPath, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxAttached,
					prometheus.GaugeValue,
					float64(boolToInt(vhdInfo.InUse)),
					vmName, controllerType, vhdPath, vhdFilename, vhdFormat, vhdType,
				)

				ch <- prometheus.MustNewConstMetric(
					c.vhdxIsPMEMCompatible,
					prometheus.GaugeValue,
					float64(boolToInt(vhdInfo.IsPMEMCompatible)),
					vmName, controllerType, vhdPath, vhdFilename, vhdFormat, vhdType,
				)
			}
		}
	}

	return nil
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
	// Query VHD settings data
	var vhdSettings []VirtualHardDiskSettingData
	settingsQuery, err := mi.NewQuery(fmt.Sprintf("SELECT * FROM Msvm_VirtualHardDiskSettingData WHERE Path = '%s'", strings.ReplaceAll(vhdPath, `\`, `\\`)))
	if err != nil {
		return nil, false
	}

	if err := c.miSession.Query(&vhdSettings, namespace, settingsQuery); err != nil {
		return nil, false
	}

	if len(vhdSettings) == 0 {
		return nil, false
	}

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
		}
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
