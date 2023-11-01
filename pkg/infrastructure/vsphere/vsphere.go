package vsphere

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/govc/importx"
	"github.com/vmware/govmomi/nfc"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/ovf"
	"github.com/vmware/govmomi/vapi/rest"
	"github.com/vmware/govmomi/vapi/tags"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"

	"github.com/openshift/installer/pkg/asset"
	"github.com/openshift/installer/pkg/infrastructure"
	"github.com/openshift/installer/pkg/tfvars"
	"github.com/openshift/installer/pkg/tfvars/vsphere"
	typesinstall "github.com/openshift/installer/pkg/types"
	typesvsphere "github.com/openshift/installer/pkg/types/vsphere"
)

type VSphereInfrastructureProvider struct{}

func InitializeProvider() infrastructure.Provider {
	return &VSphereInfrastructureProvider{}
}

func (p *VSphereInfrastructureProvider) Provision(dir string, vars []*asset.File) ([]*asset.File, error) {
	vsphereConfig := &vsphere.Config{}
	clusterConfig := &tfvars.Config{}

	for _, v := range vars {
		var err error

		filePath := path.Join(dir, v.Filename)
		file, err := os.Open(filePath)

		if err != nil {
			return nil, err

		}

		// decoder provides a rational error message if the json is screwed up.
		// whereas Unmarshal does not
		decoder := json.NewDecoder(file)
		decoder.DisallowUnknownFields()

		if v.Filename == "terraform.tfvars.json" {
			err = decoder.Decode(clusterConfig)
		}
		if v.Filename == "terraform.platform.auto.tfvars.json" {
			err = decoder.Decode(vsphereConfig)
		}

		if err != nil {
			return nil, err
		}
	}

	err := provision(vsphereConfig, clusterConfig)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (p *VSphereInfrastructureProvider) DestroyBootstrap(dir string) error {
	return nil
}

func (p *VSphereInfrastructureProvider) ExtractHostAddresses(dir string, config *typesinstall.InstallConfig, ha *infrastructure.HostAddresses) error {
	return nil
}

/*
const (
	GuestInfoIgnitionData     = "guestinfo.ignition.config.data"
	GuestInfoIgnitionEncoding = "guestinfo.ignition.config.data.encoding"
	GuestInfoHostname         = "guestinfo.hostname"
	GuestInfoDomain           = "guestinfo.domain"
	// going to ignore for now...
	GuestInfoNetworkKargs = "guestinfo.afterburn.initrd.network-kargs"
	StealClock            = "stealclock.enable"
)

*/

type VCenterConnection struct {
	Client     *govmomi.Client
	Finder     *find.Finder
	Context    context.Context
	RestClient *rest.Client
	Logout     func()

	Uri      string
	Username string
	Password string
}

func getVCenterClient(uri, username, password string) (*VCenterConnection, error) {
	logrus.Infof("In getVCenterClient")
	ctx := context.Background()

	connection := &VCenterConnection{
		Context: ctx,
	}

	u, err := soap.ParseURL(uri)
	if err != nil {
		return nil, err
	}
	connection.Username = username
	connection.Password = password
	connection.Uri = uri

	u.User = url.UserPassword(username, password)

	c, err := govmomi.NewClient(ctx, u, true)
	if err != nil {
		return nil, err
	}

	connection.RestClient = rest.NewClient(c.Client)

	err = connection.RestClient.Login(connection.Context, u.User)
	if err != nil {
		return nil, err
	}
	connection.Client = c

	connection.Finder = find.NewFinder(connection.Client.Client)

	connection.Logout = func() {
		connection.Client.Logout(connection.Context)
		connection.RestClient.Logout(connection.Context)
	}

	return connection, nil

}

func provision(vsphereConfig *vsphere.Config, clusterConfig *tfvars.Config) error {
	vmTemplateMap := make(map[string]*object.VirtualMachine)
	vcenterConnectionMap := make(map[string]*VCenterConnection)
	tagMap := make(map[string]string)

	for _, v := range vsphereConfig.VCenters {
		tempVCenterConnection, err := getVCenterClient(
			v.Server,
			v.Username,
			v.Password)

		if err != nil {
			return err
		}
		vcenterConnectionMap[v.Server] = tempVCenterConnection

		defer vcenterConnectionMap[v.Server].Logout()

		// each vcenter needs a tag and tag category
		categoryId, err := createTagCategory(vcenterConnectionMap[v.Server], clusterConfig.ClusterID)
		if err != nil {
			return err
		}

		tempTag, err := createTag(vcenterConnectionMap[v.Server], clusterConfig.ClusterID, categoryId)

		if err != nil {
			return err
		}

		tagMap[v.Server] = tempTag
	}

	for _, fd := range vsphereConfig.FailureDomainMap {
		vcenterConnection := vcenterConnectionMap[fd.Server]

		logrus.Infof("fd.Topology.Datacenter: %s", fd.Topology.Datacenter)
		logrus.Infof("fd.Topology.ComputeCluster: %s", fd.Topology.ComputeCluster)

		dc, err := vcenterConnection.Finder.Datacenter(vcenterConnection.Context, fd.Topology.Datacenter)
		if err != nil {
			return err
		}
		dcFolders, err := dc.Folders(vcenterConnection.Context)

		folderPath := path.Join(dcFolders.VmFolder.InventoryPath, clusterConfig.ClusterID)
		logrus.Infof("folderPath: %s", folderPath)

		// we must set the Folder to the infraId somewhere, we will need to remove that.
		// if we are overwriting folderPath it needs to have a slash (path)
		if strings.Contains(fd.Topology.Folder, "/") {
			folderPath = fd.Topology.Folder
		}

		folder, err := createFolder(folderPath, vcenterConnection)
		if err != nil {
			return err
		}
		vmTemplate, err := importRhcosOva(vcenterConnection, folder,
			vsphereConfig.OvaFilePath, clusterConfig.ClusterID, tagMap[fd.Server], string(vsphereConfig.DiskType), fd)
		if err != nil {
			return err
		}

		// This object.VirtualMachine is not fully defined
		vmName, err := vmTemplate.ObjectName(vcenterConnection.Context)

		if err != nil {
			return err
		}

		vmTemplateMap[vmName] = vmTemplate

		if err != nil {
			return err
		}

	}

	/*
		encodedMasterIgn := base64.StdEncoding.EncodeToString([]byte(clusterConfig.IgnitionMaster))
		encodedBootstrapIgn := base64.StdEncoding.EncodeToString([]byte(clusterConfig.IgnitionBootstrap))

		bootstrap := true

		for i := 0; i < len(vsphereConfig.ControlPlanes); i++ {
			cp := vsphereConfig.ControlPlanes[i]
			vcenterConnection := vcenterConnectionMap[cp.Workspace.Server]

			vmName := fmt.Sprintf("%s-master-%d", clusterConfig.ClusterID, i)

			encodedIgnition := encodedMasterIgn

			if bootstrap {
				if i == 0 {
					encodedIgnition = encodedBootstrapIgn
					vmName = fmt.Sprintf("%s-bootstrap", clusterConfig.ClusterID)
				}
			}

			task, err := clone(vcenterConnection, vmTemplateMap[cp.Template], cp, encodedIgnition, vmName, clusterConfig.ClusterDomain)
			if err != nil {
				return err
			}

			taskInfo, err := task.WaitForResult(vcenterConnection.Context, nil)
			if err != nil {
				return err
			}

			vmMoRef := taskInfo.Result.(types.ManagedObjectReference)
			vm := object.NewVirtualMachine(vcenterConnection.Client.Client, vmMoRef)

			err = attachTag(vcenterConnectionMap[cp.Workspace.Server], vmMoRef.Value, tagMap[cp.Workspace.Server])
			if err != nil {
				return err
			}

			datacenter, err := vcenterConnection.Finder.Datacenter(vcenterConnection.Context, cp.Workspace.Datacenter)

			if err != nil {
				return err
			}

			task, err = datacenter.PowerOnVM(vcenterConnection.Context, []types.ManagedObjectReference{vm.Reference()}, &types.OptionValue{
				Key:   string(types.ClusterPowerOnVmOptionOverrideAutomationLevel),
				Value: string(types.DrsBehaviorFullyAutomated),
			})

			if err != nil {
				return err
			}

			_, err = task.WaitForResult(vcenterConnection.Context, nil)

			if err != nil {
				return err
			}

			if bootstrap {
				if i == 0 {
					bootstrap = false
					i = -1
				}
			}
		}

	*/

	return nil
}

func createFolder(fullpath string, vconn *VCenterConnection) (*object.Folder, error) {
	logrus.Infof("In createFolder")
	dir := path.Dir(fullpath)
	base := path.Base(fullpath)

	folder, err := vconn.Finder.Folder(context.TODO(), fullpath)

	if folder == nil {
		folder, err = vconn.Finder.Folder(context.TODO(), dir)

		var notFoundError *find.NotFoundError
		if errors.As(err, &notFoundError) {
			folder, err = createFolder(dir, vconn)
			if err != nil {
				return folder, err
			}
		}

		if folder != nil {
			folder, err = folder.CreateFolder(context.TODO(), base)
			if err != nil {
				return folder, err
			}
		}
	}
	return folder, err
}

func createTagCategory(vconn *VCenterConnection, clusterId string) (string, error) {
	logrus.Infof("In createTagCategory")
	categoryName := fmt.Sprintf("openshift-%s", clusterId)

	category := tags.Category{
		Name:        categoryName,
		Description: "Added by openshift-install do not remove",
		Cardinality: "SINGLE",
		AssociableTypes: []string{
			"VirtualMachine",
			"ResourcePool",
			"Folder",
			"Datastore",
			"StoragePod",
		},
	}

	return tags.NewManager(vconn.RestClient).CreateCategory(vconn.Context, &category)
}

func createTag(vconn *VCenterConnection, clusterId, categoryId string) (string, error) {
	logrus.Infof("In createTag")

	tag := tags.Tag{
		Description: "Added by openshift-install do not remove",
		Name:        clusterId,
		CategoryID:  categoryId,
	}

	return tags.NewManager(vconn.RestClient).CreateTag(vconn.Context, &tag)
}

func importRhcosOva(vconn *VCenterConnection, folder *object.Folder, cachedImage, clusterId, tagId, diskProvisioningType string, failureDomain typesvsphere.FailureDomain) (*object.VirtualMachine, error) {
	logrus.Infof("In importRhcosOva")
	name := fmt.Sprintf("%s-rhcos-%s-%s", clusterId, failureDomain.Region, failureDomain.Zone)

	archive := &importx.ArchiveFlag{Archive: &importx.TapeArchive{Path: cachedImage}}

	ovfDescriptor, err := archive.ReadOvf("*.ovf")
	if err != nil {
		// Open the corrupt OVA file
		f, ferr := os.Open(cachedImage)
		if ferr != nil {
			err = fmt.Errorf("%s, %w", err.Error(), ferr)
		}
		defer f.Close()

		// Get a sha256 on the corrupt OVA file
		// and the size of the file
		h := sha256.New()
		written, cerr := io.Copy(h, f)
		if cerr != nil {
			err = fmt.Errorf("%s, %w", err.Error(), cerr)
		}

		return nil, errors.Errorf("ova %s has a sha256 of %x and a size of %d bytes, failed to read the ovf descriptor %s", cachedImage, h.Sum(nil), written, err)
	}

	ovfEnvelope, err := archive.ReadEnvelope(ovfDescriptor)
	if err != nil {
		return nil, errors.Errorf("failed to parse ovf: %s", err)
	}

	// The RHCOS OVA only has one network defined by default
	// The OVF envelope defines this.  We need a 1:1 mapping
	// between networks with the OVF and the host
	if len(ovfEnvelope.Network.Networks) != 1 {
		return nil, errors.Errorf("Expected the OVA to only have a single network adapter")
	}

	cluster, err := vconn.Finder.ClusterComputeResource(vconn.Context, failureDomain.Topology.ComputeCluster)

	if err != nil {
		return nil, err
	}
	clusterHostSystems, err := cluster.Hosts(vconn.Context)

	if err != nil {
		return nil, err
	}
	resourcePool, err := vconn.Finder.ResourcePool(vconn.Context, failureDomain.Topology.ResourcePool)

	networkPath := path.Join(cluster.InventoryPath, failureDomain.Topology.Networks[0])

	networkRef, err := vconn.Finder.Network(vconn.Context, networkPath)
	if err != nil {
		return nil, err
	}
	datastore, err := vconn.Finder.Datastore(vconn.Context, failureDomain.Topology.Datastore)

	// Create mapping between OVF and the network object
	// found by Name
	networkMappings := []types.OvfNetworkMapping{{
		Name:    ovfEnvelope.Network.Networks[0].Name,
		Network: networkRef.Reference(),
	}}

	// This is a very minimal spec for importing an OVF.
	cisp := types.OvfCreateImportSpecParams{
		EntityName:     name,
		NetworkMapping: networkMappings,
	}

	m := ovf.NewManager(vconn.Client.Client)
	spec, err := m.CreateImportSpec(vconn.Context,
		string(ovfDescriptor),
		resourcePool.Reference(),
		datastore.Reference(),
		cisp)

	if err != nil {
		return nil, errors.Errorf("failed to create import spec: %s", err)
	}
	if spec.Error != nil {
		return nil, errors.New(spec.Error[0].LocalizedMessage)
	}

	hostSystem, err := findAvailableHostSystems(vconn, clusterHostSystems)

	if err != nil {
		return nil, err
	}

	lease, err := resourcePool.ImportVApp(vconn.Context, spec.ImportSpec, folder, hostSystem)

	if err != nil {
		return nil, errors.Errorf("failed to import vapp: %s", err)
	}

	info, err := lease.Wait(vconn.Context, spec.FileItem)
	if err != nil {
		return nil, errors.Errorf("failed to lease wait: %s", err)
	}

	if err != nil {
		return nil, errors.Errorf("failed to attach tag to virtual machine: %s", err)
	}

	u := lease.StartUpdater(vconn.Context, info)
	defer u.Done()

	for _, i := range info.Items {
		// upload the vmdk to which ever host that was first
		// available with the required network and datastore.
		err = upload(vconn.Context, archive, lease, i)
		if err != nil {
			return nil, errors.Errorf("failed to upload: %s", err)
		}
	}

	err = lease.Complete(vconn.Context)
	if err != nil {
		return nil, errors.Errorf("failed to lease complete: %s", err)
	}

	vm := object.NewVirtualMachine(vconn.Client.Client, info.Entity)
	if vm == nil {
		return nil, fmt.Errorf("error VirtualMachine not found, managed object id: %s", info.Entity.Value)
	}

	err = vm.MarkAsTemplate(vconn.Context)
	if err != nil {
		return nil, errors.Errorf("failed to mark vm as template: %s", err)
	}
	err = attachTag(vconn, vm.Reference().Value, tagId)
	if err != nil {
		return nil, err
	}

	return vm, nil
}

func findAvailableHostSystems(vconn *VCenterConnection, clusterHostSystems []*object.HostSystem) (*object.HostSystem, error) {
	logrus.Infof("In findAvailableHostSystems")
	var hostSystemManagedObject mo.HostSystem
	for _, hostObj := range clusterHostSystems {
		err := hostObj.Properties(vconn.Context, hostObj.Reference(), []string{"config.product", "network", "datastore", "runtime"}, &hostSystemManagedObject)
		if err != nil {
			return nil, err
		}
		if hostSystemManagedObject.Runtime.InMaintenanceMode {
			continue
		}
		return hostObj, nil
	}
	return nil, errors.New("all hosts unavailable")
}

// Used govc/importx/ovf.go as an example to implement
// resourceVspherePrivateImportOvaCreate and upload functions
// See: https://github.com/vmware/govmomi/blob/cc10a0758d5b4d4873388bcea417251d1ad03e42/govc/importx/ovf.go#L196-L324
func upload(ctx context.Context, archive *importx.ArchiveFlag, lease *nfc.Lease, item nfc.FileItem) error {
	logrus.Infof("In upload")
	file := item.Path

	f, size, err := archive.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	opts := soap.Upload{
		ContentLength: size,
	}

	return lease.Upload(ctx, item, f, opts)
}

func attachTag(vconn *VCenterConnection, vmMoRefValue, tagId string) error {
	logrus.Infof("In attachTag")
	tagManager := tags.NewManager(vconn.RestClient)
	moRef := types.ManagedObjectReference{
		Value: vmMoRefValue,
		Type:  "VirtualMachine",
	}

	err := tagManager.AttachTag(vconn.Context, tagId, moRef)

	if err != nil {
		return err
	}
	return nil
}

/*
func getExtraConfig(vmName, clusterDomain, encodedIgnition string) []types.BaseOptionValue {
	return []types.BaseOptionValue{
		&types.OptionValue{
			Key:   GuestInfoIgnitionEncoding,
			Value: "base64",
		},
		&types.OptionValue{
			Key:   GuestInfoIgnitionData,
			Value: encodedIgnition,
		},
		&types.OptionValue{
			Key:   GuestInfoHostname,
			Value: vmName,
		},
		&types.OptionValue{
			Key:   StealClock,
			Value: "TRUE",
		},
		&types.OptionValue{
			Key:   GuestInfoDomain,
			Value: clusterDomain,
		},
	}
}

func clone(vconn *VCenterConnection,
	vmTemplate *object.VirtualMachine,
	machineProviderSpec *machinev1beta1.VSphereMachineProviderSpec,
	encodedIgnition, vmName, clusterDomain string) (*object.Task, error) {

	extraConfig := getExtraConfig(vmName, clusterDomain, encodedIgnition)

	var deviceSpecs []types.BaseVirtualDeviceConfigSpec
	virtualDeviceList, err := vmTemplate.Device(vconn.Context)
	if err != nil {
		return nil, err
	}

	diskSpec, err := getDiskSpec(virtualDeviceList, machineProviderSpec)
	if err != nil {
		return nil, err
	}
	deviceSpecs = append(deviceSpecs, diskSpec)

	networkDevices, err := getNetworkDevices(vconn, virtualDeviceList, machineProviderSpec)
	if err != nil {
		return nil, err
	}

	deviceSpecs = append(deviceSpecs, networkDevices...)

	datastore, err := vconn.Finder.Datastore(vconn.Context, machineProviderSpec.Workspace.Datastore)
	if err != nil {
		return nil, err
	}
	folder, err := vconn.Finder.Folder(vconn.Context, machineProviderSpec.Workspace.Folder)
	if err != nil {
		return nil, err
	}
	resourcepool, err := vconn.Finder.ResourcePool(vconn.Context, machineProviderSpec.Workspace.ResourcePool)

	diskUuidEnabled := true
	spec := types.VirtualMachineCloneSpec{
		Config: &types.VirtualMachineConfigSpec{
			Flags: &types.VirtualMachineFlagInfo{
				DiskUuidEnabled: &diskUuidEnabled,
			},
			ExtraConfig:       extraConfig,
			DeviceChange:      deviceSpecs,
			NumCPUs:           machineProviderSpec.NumCPUs,
			NumCoresPerSocket: machineProviderSpec.NumCoresPerSocket,
			MemoryMB:          machineProviderSpec.MemoryMiB,
		},
		Location: types.VirtualMachineRelocateSpec{
			Datastore: types.NewReference(datastore.Reference()),
			Folder:    types.NewReference(folder.Reference()),
			Pool:      types.NewReference(resourcepool.Reference()),
		},
		PowerOn: false,
	}

	return vmTemplate.Clone(vconn.Context, folder, vmName, spec)
}

func getDiskSpec(devices object.VirtualDeviceList, machineProviderSpec *machinev1beta1.VSphereMachineProviderSpec) (types.BaseVirtualDeviceConfigSpec, error) {
	disks := devices.SelectByType((*types.VirtualDisk)(nil))

	disk := disks[0].(*types.VirtualDisk)
	cloneCapacityKB := int64(machineProviderSpec.DiskGiB) * 1024 * 1024
	disk.CapacityInKB = cloneCapacityKB

	return &types.VirtualDeviceConfigSpec{
		Operation: types.VirtualDeviceConfigSpecOperationEdit,
		Device:    disk,
	}, nil
}

func getNetworkDevices(
	vconn *VCenterConnection,
	devices object.VirtualDeviceList,
	machineProviderSpec *machinev1beta1.VSphereMachineProviderSpec) ([]types.BaseVirtualDeviceConfigSpec, error) {
	var networkDevices []types.BaseVirtualDeviceConfigSpec

	nics := devices.SelectByType(&types.VirtualEthernetCard{})

	nic := nics[0].(*types.VirtualVmxnet3)

	// I am sure there is a better way to do this...
	networkType := "Network"
	if strings.Contains(machineProviderSpec.Network.Devices[0].NetworkName, "dv") {
		networkType = "DistributedVirtualPortgroup"
	}
	networkObjRef := types.ManagedObjectReference{
		Value: machineProviderSpec.Network.Devices[0].NetworkName,
		Type:  networkType,
	}

	// if this doesn't error with NotFoundError, then the NetworkName
	// in the ManagedObjectReference is a Value string vs a path
	networkObject, err := vconn.Finder.ObjectReference(vconn.Context, networkObjRef)

	// I am unsure we care about this scenario
	//var notFoundError *find.NotFoundError
	if err != nil {
		//if errors.As(err, &notFoundError) {
		//return getNetworkDevicesByPath(vconn, devices, machineProviderSpec)
		//} else {
		return nil, err
		//}
	}
	var backing types.BaseVirtualDeviceBackingInfo

	switch networkObject.(type) {
	case object.DistributedVirtualPortgroup:
		backing, err = networkObject.(object.DistributedVirtualPortgroup).EthernetCardBackingInfo(vconn.Context)
	case object.Network:
		backing, err = networkObject.(object.Network).EthernetCardBackingInfo(vconn.Context)
	}

	if err != nil {
		return nil, err
	}

	newNicDevice, err := object.EthernetCardTypes().CreateEthernetCard("vmxnet3", backing)
	if err != nil {
		return nil, err
	}
	card := newNicDevice.(types.BaseVirtualEthernetCard).GetVirtualEthernetCard()
	card.Key = int32(1)

	card.MacAddress = ""
	card.AddressType = string(types.VirtualEthernetCardMacTypeGenerated)

	nic.Backing = card.Backing

	networkDevices = append(networkDevices, &types.VirtualDeviceConfigSpec{
		Device:    nic,
		Operation: types.VirtualDeviceConfigSpecOperationEdit,
	})
	return networkDevices, nil
}

*/

/*
func getNetworkDevicesByPath(vconn *VCenterConnection,
	devices object.VirtualDeviceList,
	machineProviderSpec *machinev1beta1.VSphereMachineProviderSpec) ([]types.BaseVirtualDeviceConfigSpec, error) {

	var networkDevices []types.BaseVirtualDeviceConfigSpec
	resourcepool, err := vconn.Finder.ResourcePool(vconn.Context, machineProviderSpec.Workspace.ResourcePool)
	if err != nil {
		return nil, err
	}

	clusterObjRef, err := resourcepool.Owner(vconn.Context)
	if err != nil {
		return nil, err
	}

	computeCluster := clusterObjRef.(*object.ClusterComputeResource)
	if computeCluster.InventoryPath == "" {
		clusterObjRef, err = vconn.Finder.ObjectReference(vconn.Context, clusterObjRef.Reference())
		if err != nil {
			return nil, err
		}
		computeCluster = clusterObjRef.(*object.ClusterComputeResource)
	}

	netdev := machineProviderSpec.Network.Devices[0]
	networkPath := path.Join(computeCluster.InventoryPath, netdev.NetworkName)
	networkObject, err := vconn.Finder.Network(vconn.Context, networkPath)
	if err != nil {
		return nil, err
	}
	backing, err := networkObject.EthernetCardBackingInfo(vconn.Context)
	if err != nil {
		return nil, err
	}

	newNicDevice, err := object.EthernetCardTypes().CreateEthernetCard("vmxnet3", backing)
	card := newNicDevice.(types.BaseVirtualEthernetCard).GetVirtualEthernetCard()

	card.MacAddress = ""
	card.AddressType = string(types.VirtualEthernetCardMacTypeGenerated)

	networkDevices = append(networkDevices, &types.VirtualDeviceConfigSpec{
		Device:    newNicDevice,
		Operation: types.VirtualDeviceConfigSpecOperationAdd,
	})

		device, err := object.EthernetCardTypes().CreateEthernetCard("vmxnet3", backing)
		changed := device.(types.BaseVirtualEthernetCard).GetVirtualEthernetCard()

		changed.MacAddress = ""
		changed.AddressType = string(types.VirtualEthernetCardMacTypeGenerated)

		nic.Backing = changed.Backing
		nic.AddressType = string(types.VirtualEthernetCardMacTypeGenerated)
		nic.MacAddress = ""

		networkDevices = append(networkDevices, &types.VirtualDeviceConfigSpec{
			Device:    nic,
			Operation: types.VirtualDeviceConfigSpecOperationEdit,
		})

	return networkDevices, nil

}
*/
