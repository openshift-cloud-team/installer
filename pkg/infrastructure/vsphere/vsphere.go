package vsphere

import (
	"encoding/json"
	"log"
	"os"

	"github.com/openshift/installer/pkg/asset"
	"github.com/openshift/installer/pkg/infrastructure"
	"github.com/openshift/installer/pkg/tfvars"
	"github.com/openshift/installer/pkg/tfvars/vsphere"
	"github.com/openshift/installer/pkg/types"
)

// Now the question, do we copy these or just import?
// pkg/tfvars/tfvars.go

/*
type Config struct {
	ClusterID          string   `json:"cluster_id,omitempty"`
	ClusterDomain      string   `json:"cluster_domain,omitempty"`
	BaseDomain         string   `json:"base_domain,omitempty"`
	Masters            int      `json:"master_count,omitempty"`
	MastersSchedulable bool     `json:"masters_schedulable,omitempty"`
	MachineV4CIDRs     []string `json:"machine_v4_cidrs"`
	MachineV6CIDRs     []string `json:"machine_v6_cidrs"`

	UseIPv4 bool `json:"use_ipv4"`
	UseIPv6 bool `json:"use_ipv6"`

	IgnitionBootstrap     string `json:"ignition_bootstrap,omitempty"`
	IgnitionBootstrapFile string `json:"ignition_bootstrap_file,omitempty"`
	IgnitionMaster        string `json:"ignition_master,omitempty"`
}

// pkg/tfvars/vsphere/vsphere.go
type folder struct {
	Name       string `json:"name"`
	Datacenter string `json:"vsphere_datacenter"`
}
type VSphereConfig struct {
	OvaFilePath              string                                   `json:"vsphere_ova_filepath"`
	DiskType                 vtypes.DiskType                          `json:"vsphere_disk_type"`
	VCenters                 map[string]vtypes.VCenter                `json:"vsphere_vcenters"`
	NetworksInFailureDomains map[string]string                        `json:"vsphere_networks"`
	ControlPlanes            []*machineapi.VSphereMachineProviderSpec `json:"vsphere_control_planes"`
	ControlPlaneNetworkKargs []string                                 `json:"vsphere_control_plane_network_kargs"`
	BootStrapNetworkKargs    string                                   `json:"vsphere_bootstrap_network_kargs"`
	DatacentersFolders       map[string]*folder                       `json:"vsphere_folders"`

	ImportOvaFailureDomainMap map[string]vtypes.FailureDomain `json:"vsphere_import_ova_failure_domain_map"`
	FailureDomainMap          map[string]vtypes.FailureDomain `json:"vsphere_failure_domain_map"`
}

*/

type VSphereInfrastructureProvider struct {
}

func InitializeProvider() infrastructure.Provider {
	return &VSphereInfrastructureProvider{}
}

func (p *VSphereInfrastructureProvider) Provision(dir string, vars []*asset.File) ([]*asset.File, error) {
	vsphereConfig := &vsphere.Config{}
	clusterConfig := &tfvars.Config{}

	for _, v := range vars {
		var err error

		file, err := os.Open(v.Filename)

		if err != nil {
			return nil, err

		}

		decoder := json.NewDecoder(file)
		decoder.DisallowUnknownFields()

		if v.Filename == "terraform.tfvars.json" {
			err = json.Unmarshal(v.Data, clusterConfig)
			err = decoder.Decode(clusterConfig)
		}
		if v.Filename == "terraform.platform.auto.tfvars.json" {
			err = json.Unmarshal(v.Data, vsphereConfig)
			err = decoder.Decode(vsphereConfig)
		}

		if err != nil {
			return nil, err
		}
	}

	for _, cp := range vsphereConfig.ControlPlanes {
		log.Printf("cp name: %s", cp.Name)
	}

	return nil, nil
}

func (p *VSphereInfrastructureProvider) DestroyBootstrap(dir string) error {

	return nil
}

func (p *VSphereInfrastructureProvider) ExtractHostAddresses(dir string, config *types.InstallConfig, ha *infrastructure.HostAddresses) error {
	return nil
}
