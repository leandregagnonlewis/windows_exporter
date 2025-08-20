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
	"github.com/yusufpapurcu/wmi"
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

	// Simpler storage query without LIKE operator that may not be supported
	var testVMs []miVirtualSystemSettingData
	storageQuery := wmi.CreateQuery("testVMS", "Parent IS NOT NULL", "VirtualSystemSettingData")
	c.storageQuery = storageQuery

	// Test the queries to make sure they work - following cpu_info.go pattern
	hypervNamespace, err := mi.NewNamespace("root/virtualization/v2")
	if err != nil {
		return fmt.Errorf("failed to create Hyper-V namespace: %w", err)
	}

	if err := c.miSession.Query(&testVMs, hypervNamespace, c.vmQuery); err != nil {
		return fmt.Errorf("VM WMI query failed: %w", err)
	}

	var testStorage []miStorageAllocationSettingData
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

	// Query storage allocation data using the prepared query
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

			// Emit the exists metric
			ch <- prometheus.MustNewConstMetric(
				c.vhdxExists,
				prometheus.GaugeValue,
				1, // We found it
				vmName, controllerType, controllerNumber, controllerLocation, hostResource, vhdFilename,
			)

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
