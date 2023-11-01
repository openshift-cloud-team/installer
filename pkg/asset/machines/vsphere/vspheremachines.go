// Package aws generates Machine objects for aws.
package vsphere

import (
	"context"
	"encoding/json"
	"fmt"
	"path"

	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vapi/tags"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/session"

	machinev1 "github.com/openshift/api/machine/v1beta1"

	capv "sigs.k8s.io/cluster-api-provider-vsphere/apis/v1beta1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/installer/pkg/types"
)

const (
	capiGuestsNamespace = "openshift-cluster-api-guests"
)

// ProviderSpecFromRawExtension unmarshals the JSON-encoded spec
func ProviderSpecFromRawExtension(rawExtension *runtime.RawExtension) (*machinev1.VSphereMachineProviderSpec, error) {
	if rawExtension == nil {
		return &machinev1.VSphereMachineProviderSpec{}, nil
	}

	spec := new(machinev1.VSphereMachineProviderSpec)
	if err := json.Unmarshal(rawExtension.Raw, &spec); err != nil {
		return nil, fmt.Errorf("error unmarshalling providerSpec: %v", err)
	}

	//klog.V(5).Infof("Got provider spec from raw extension: %+v", spec)
	return spec, nil
}

func createClusterTagID(ctx context.Context, session *session.Session, clusterId string, config *types.InstallConfig) (string, error) {
	tagManager := session.TagManager
	categories, err := tagManager.GetCategories(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to get tag categories: %v", err)
	}

	var clusterTagCategory *tags.Category
	clusterTagCategoryName := fmt.Sprintf("openshift-%s", clusterId)
	tagCategoryId := ""

	for _, category := range categories {
		if category.Name == clusterTagCategoryName {
			clusterTagCategory = &category
			tagCategoryId = category.ID
			break
		}
	}

	if clusterTagCategory == nil {
		clusterTagCategory = &tags.Category{
			Name:        clusterTagCategoryName,
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
		tagCategoryId, err = tagManager.CreateCategory(ctx, clusterTagCategory)
		if err != nil {
			return "", fmt.Errorf("unable to create tag category: %v", err)
		}
	}

	var categoryTag *tags.Tag
	tagId := ""

	categoryTags, err := tagManager.GetTagsForCategory(ctx, tagCategoryId)
	if err != nil {
		return "", fmt.Errorf("unable to get tags for category: %v", err)
	}
	for _, tag := range categoryTags {
		if tag.Name == clusterId {
			categoryTag = &tag
			tagId = tag.ID
			break
		}
	}

	if categoryTag == nil {
		categoryTag = &tags.Tag{
			Description: "Added by openshift-install do not remove",
			Name:        clusterId,
			CategoryID:  tagCategoryId,
		}
		tagId, err = tagManager.CreateTag(ctx, categoryTag)
		if err != nil {
			return "", fmt.Errorf("unable to create tag: %v", err)
		}
	}

	return tagId, nil
}

func createConnections(ctx context.Context, config *types.InstallConfig) (map[string]*session.Session, error) {
	connections := make(map[string]*session.Session)
	for _, v := range config.VSphere.VCenters {
		params := session.NewParams().WithServer(v.Server).WithUserInfo(v.Username, v.Password)

		tempConnection, err := session.GetOrCreate(ctx, params)

		if err != nil {
			return nil, err
		}
		connections[v.Server] = tempConnection
	}
	return connections, nil
}

// Machines returns a list of machines for a machinepool.
func VSphereMachines(ctx context.Context, clusterID string, config *types.InstallConfig, pool *types.MachinePool, osImage, role, userDataSecret string) ([]client.Object, []capv.VSphereMachine, error) {
	machines, err := Machines(clusterID, config, pool, osImage, role, userDataSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to retrieve machines: %w", err)
	}

	connections, err := createConnections(ctx, config)

	if err != nil {
		return nil, nil, err
	}

	var result []client.Object
	var vsphereMachines []capv.VSphereMachine

	for _, machine := range machines {
		providerSpec := machine.Spec.ProviderSpec.Value.Object.(*machinev1.VSphereMachineProviderSpec)

		conn := connections[providerSpec.Workspace.Server]

		tagId, err := createClusterTagID(ctx, conn, clusterID, config)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get cluster tag ID: %v", err)
		}

		rp, err := conn.Finder.ResourcePool(ctx, providerSpec.Workspace.ResourcePool)
		if err != nil {
			return nil, nil, err
		}

		clusterRef, err := rp.Owner(ctx)

		if err != nil {
			return nil, nil, err
		}

		clusterObjRef, err := conn.Finder.ObjectReference(ctx, clusterRef.Reference())
		if err != nil {
			return nil, nil, err
		}

		networkName := path.Join(clusterObjRef.(*object.ClusterComputeResource).InventoryPath, providerSpec.Network.Devices[0].NetworkName)

		vsphereMachine := &capv.VSphereMachine{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "infrastructure.cluster.x-k8s.io/v1beta1",
				Kind:       "VSphereMachine",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: capiGuestsNamespace,
				Name:      machine.Name,
				Labels: map[string]string{
					"cluster.x-k8s.io/control-plane": "",
				},
			},
			Spec: capv.VSphereMachineSpec{

				VirtualMachineCloneSpec: capv.VirtualMachineCloneSpec{
					CustomVMXKeys: map[string]string{
						"guestinfo.hostname": machine.Name,
					},
					TagIDs: []string{
						tagId,
					},
					Network: capv.NetworkSpec{
						Devices: []capv.NetworkDeviceSpec{
							{
								NetworkName: networkName,
								DHCP4:       true,
							},
						},
					},
					Folder:       providerSpec.Workspace.Folder,
					Template:     providerSpec.Template,
					Datacenter:   providerSpec.Workspace.Datacenter,
					Server:       providerSpec.Workspace.Server,
					NumCPUs:      providerSpec.NumCPUs,
					MemoryMiB:    providerSpec.MemoryMiB,
					DiskGiB:      providerSpec.DiskGiB,
					Datastore:    providerSpec.Workspace.Datastore,
					ResourcePool: providerSpec.Workspace.ResourcePool,
				},
			},
		}

		vsphereMachines = append(vsphereMachines, *vsphereMachine)
		machine := &capi.Machine{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: capiGuestsNamespace,
				Name:      vsphereMachine.Name,
				Labels: map[string]string{
					"cluster.x-k8s.io/control-plane": "",
				},
			},
			Spec: capi.MachineSpec{
				ClusterName: clusterID,
				Bootstrap: capi.Bootstrap{
					DataSecretName: pointer.String(fmt.Sprintf("%s-%s", clusterID, role)),
				},
				InfrastructureRef: v1.ObjectReference{
					APIVersion: "infrastructure.cluster.x-k8s.io/v1beta1",
					Kind:       "VSphereMachine",
					Name:       vsphereMachine.Name,
				},
			},
		}

		result = append(result, vsphereMachine, machine)
	}

	return result, vsphereMachines, nil
}
