// Package aws generates Machine objects for aws.
package vsphere

import (
	"encoding/json"
	"fmt"
	"strings"

	machinev1 "github.com/openshift/api/machine/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"

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

// Machines returns a list of machines for a machinepool.
func VSphereMachines(clusterID string, config *types.InstallConfig, pool *types.MachinePool, osImage, role, userDataSecret string) ([]client.Object, []capv.VSphereMachine, error) {
	machines, err := Machines(clusterID, config, pool, osImage, role, userDataSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to retrieve machines: %w", err)
	}

	var result []client.Object
	var vsphereMachines []capv.VSphereMachine

	for _, machine := range machines {
		providerSpec := machine.Spec.ProviderSpec.Value.Object.(*machinev1.VSphereMachineProviderSpec)

		clusterPath := providerSpec.Workspace.ResourcePool
		lastElement := strings.LastIndex(clusterPath, "/")
		if lastElement != -1 {
			clusterPath = clusterPath[:lastElement]
		}
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
					Network: capv.NetworkSpec{
						Devices: []capv.NetworkDeviceSpec{
							{
								NetworkName: fmt.Sprintf("%s/%s", clusterPath, providerSpec.Network.Devices[0].NetworkName),
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
