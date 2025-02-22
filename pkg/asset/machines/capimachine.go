package machines

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	capa "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/installer/pkg/asset"
	"github.com/openshift/installer/pkg/asset/ignition/machine"
	"github.com/openshift/installer/pkg/asset/installconfig"
	"github.com/openshift/installer/pkg/asset/machines/aws"
	"github.com/openshift/installer/pkg/asset/rhcos"
	awstypes "github.com/openshift/installer/pkg/types/aws"
	awsdefaults "github.com/openshift/installer/pkg/types/aws/defaults"
)

// Master generates the machines for the `master` machine pool.
type CAPIMachine struct {
	Machines []client.Object `json:"-"`
}

// Name returns a human friendly name for the Master Asset.
func (m *CAPIMachine) Name() string {
	return "CAPI Machines"
}

// Dependencies returns all of the dependencies directly needed by the
// Master asset.
func (m *CAPIMachine) Dependencies() []asset.Asset {
	return []asset.Asset{
		&installconfig.ClusterID{},
		// PlatformCredsCheck just checks the creds (and asks, if needed)
		// We do not actually use it in this asset directly, hence
		// it is put in the dependencies but not fetched in Generate
		// &installconfig.PlatformCredsCheck{},
		&installconfig.InstallConfig{},
		new(rhcos.Image),
		&machine.Master{},
	}
}

// Generate generates the Master asset.
func (m *CAPIMachine) Generate(dependencies asset.Parents) error {
	ctx := context.TODO()
	clusterID := &installconfig.ClusterID{}
	installConfig := &installconfig.InstallConfig{}
	rhcosImage := new(rhcos.Image)
	mign := &machine.Master{}
	dependencies.Get(clusterID, installConfig, rhcosImage, mign)

	ic := installConfig.Config

	pool := *ic.ControlPlane
	var err error

	switch ic.Platform.Name() {
	case awstypes.Name:
		subnets := map[string]string{}
		if len(ic.Platform.AWS.Subnets) > 0 {
			subnetMeta, err := installConfig.AWS.PrivateSubnets(ctx)
			if err != nil {
				return err
			}
			for id, subnet := range subnetMeta {
				subnets[subnet.Zone.Name] = id
			}
		}

		mpool := defaultAWSMachinePoolPlatform("master")

		osImage := strings.SplitN(string(*rhcosImage), ",", 2)
		osImageID := osImage[0]
		if len(osImage) == 2 {
			osImageID = "" // the AMI will be generated later on
		}
		mpool.AMIID = osImageID

		mpool.Set(ic.Platform.AWS.DefaultMachinePlatform)
		mpool.Set(pool.Platform.AWS)
		zoneDefaults := false
		if len(mpool.Zones) == 0 {
			if len(subnets) > 0 {
				for zone := range subnets {
					mpool.Zones = append(mpool.Zones, zone)
				}
			} else {
				mpool.Zones, err = installConfig.AWS.AvailabilityZones(ctx)
				if err != nil {
					return err
				}
				zoneDefaults = true
			}
		}

		if mpool.InstanceType == "" {
			topology := configv1.HighlyAvailableTopologyMode
			if pool.Replicas != nil && *pool.Replicas == 1 {
				topology = configv1.SingleReplicaTopologyMode
			}
			mpool.InstanceType, err = aws.PreferredInstanceType(ctx, installConfig.AWS, awsdefaults.InstanceTypes(installConfig.Config.Platform.AWS.Region, installConfig.Config.ControlPlane.Architecture, topology), mpool.Zones)
			if err != nil {
				logrus.Warn(errors.Wrap(err, "failed to find default instance type"))
				mpool.InstanceType = awsdefaults.InstanceTypes(installConfig.Config.Platform.AWS.Region, installConfig.Config.ControlPlane.Architecture, topology)[0]
			}
		}

		// if the list of zones is the default we need to try to filter the list in case there are some zones where the instance might not be available
		if zoneDefaults {
			mpool.Zones, err = aws.FilterZonesBasedOnInstanceType(ctx, installConfig.AWS, mpool.InstanceType, mpool.Zones)
			if err != nil {
				logrus.Warn(errors.Wrap(err, "failed to filter zone list"))
			}
		}

		pool.Platform.AWS = &mpool
		awsMachines, err := aws.AWSMachines(
			clusterID.InfraID,
			installConfig.Config.Platform.AWS.Region,
			subnets,
			&pool,
			"master",
			installConfig.Config.Platform.AWS.UserTags,
		)
		if err != nil {
			return errors.Wrap(err, "failed to create master machine objects")
		}
		m.Machines = append(m.Machines, awsMachines...)

		// TODO(vincepri): The following code is almost duplicated from aws.AWSMachines.
		// Refactor and generalize around a bootstrap pool, with a single machine and
		// a custom openshift label to determine the bootstrap machine role, so we can
		// delete the machine when the stage is complete.
		bootstrapAWSMachine := &capa.AWSMachine{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("%s-%s-bootstrap", clusterID.InfraID, pool.Name),
				Labels: map[string]string{
					"cluster.x-k8s.io/control-plane": "",
				},
			},
			Spec: capa.AWSMachineSpec{
				Ignition:             &capa.Ignition{Version: "3.2"},
				UncompressedUserData: pointer.Bool(true),
				InstanceType:         mpool.InstanceType,
				AMI:                  capa.AMIReference{ID: pointer.String(mpool.AMIID)},
				SSHKeyName:           pointer.String(""),
				IAMInstanceProfile:   fmt.Sprintf("%s-master-profile", clusterID.InfraID),
				PublicIP:             pointer.Bool(true),
				RootVolume: &capa.Volume{
					Size:          int64(mpool.EC2RootVolume.Size),
					Type:          capa.VolumeType(mpool.EC2RootVolume.Type),
					IOPS:          int64(mpool.EC2RootVolume.IOPS),
					Encrypted:     pointer.Bool(true),
					EncryptionKey: mpool.KMSKeyARN,
				},
			},
		}

		// Handle additional security groups.
		for _, sg := range mpool.AdditionalSecurityGroupIDs {
			bootstrapAWSMachine.Spec.AdditionalSecurityGroups = append(
				bootstrapAWSMachine.Spec.AdditionalSecurityGroups,
				capa.AWSResourceReference{ID: pointer.String(sg)},
			)
		}

		bootstrapMachine := &capi.Machine{
			ObjectMeta: metav1.ObjectMeta{
				Name: bootstrapAWSMachine.Name,
				Labels: map[string]string{
					"cluster.x-k8s.io/control-plane": "",
				},
			},
			Spec: capi.MachineSpec{
				ClusterName: clusterID.InfraID,
				Bootstrap: capi.Bootstrap{
					DataSecretName: pointer.String(fmt.Sprintf("%s-%s", clusterID.InfraID, "bootstrap")),
				},
				InfrastructureRef: v1.ObjectReference{
					APIVersion: "infrastructure.cluster.x-k8s.io/v1beta2",
					Kind:       "AWSMachine",
					Name:       bootstrapAWSMachine.Name,
				},
			},
		}

		m.Machines = append(m.Machines, bootstrapAWSMachine, bootstrapMachine)
	default:
		return nil
	}
	return nil
}
