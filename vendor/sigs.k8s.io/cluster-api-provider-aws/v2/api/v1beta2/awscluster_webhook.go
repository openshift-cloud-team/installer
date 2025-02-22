/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta2

import (
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util/annotations"
)

// log is for logging in this package.
var _ = ctrl.Log.WithName("awscluster-resource")

func (r *AWSCluster) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// +kubebuilder:webhook:verbs=create;update,path=/validate-infrastructure-cluster-x-k8s-io-v1beta2-awscluster,mutating=false,failurePolicy=fail,matchPolicy=Equivalent,groups=infrastructure.cluster.x-k8s.io,resources=awsclusters,versions=v1beta2,name=validation.awscluster.infrastructure.cluster.x-k8s.io,sideEffects=None,admissionReviewVersions=v1;v1beta1
// +kubebuilder:webhook:verbs=create;update,path=/mutate-infrastructure-cluster-x-k8s-io-v1beta2-awscluster,mutating=true,failurePolicy=fail,matchPolicy=Equivalent,groups=infrastructure.cluster.x-k8s.io,resources=awsclusters,versions=v1beta2,name=default.awscluster.infrastructure.cluster.x-k8s.io,sideEffects=None,admissionReviewVersions=v1;v1beta1

var (
	_ webhook.Validator = &AWSCluster{}
	_ webhook.Defaulter = &AWSCluster{}
)

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type.
func (r *AWSCluster) ValidateCreate() (admission.Warnings, error) {
	var allErrs field.ErrorList

	allErrs = append(allErrs, r.Spec.Bastion.Validate()...)
	allErrs = append(allErrs, r.validateSSHKeyName()...)
	allErrs = append(allErrs, r.Spec.AdditionalTags.Validate()...)
	allErrs = append(allErrs, r.Spec.S3Bucket.Validate()...)
	allErrs = append(allErrs, r.validateNetwork()...)
	allErrs = append(allErrs, r.validateControlPlaneLB()...)

	return nil, aggregateObjErrors(r.GroupVersionKind().GroupKind(), r.Name, allErrs)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type.
func (r *AWSCluster) ValidateDelete() (admission.Warnings, error) {
	return nil, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type.
func (r *AWSCluster) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	var allErrs field.ErrorList

	allErrs = append(allErrs, r.validateGCTasksAnnotation()...)

	oldC, ok := old.(*AWSCluster)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("expected an AWSCluster but got a %T", old))
	}

	if r.Spec.Region != oldC.Spec.Region {
		allErrs = append(allErrs,
			field.Invalid(field.NewPath("spec", "region"), r.Spec.Region, "field is immutable"),
		)
	}

	newLoadBalancer := &AWSLoadBalancerSpec{}
	existingLoadBalancer := &AWSLoadBalancerSpec{}

	if r.Spec.ControlPlaneLoadBalancer != nil {
		newLoadBalancer = r.Spec.ControlPlaneLoadBalancer.DeepCopy()
	}

	if oldC.Spec.ControlPlaneLoadBalancer != nil {
		existingLoadBalancer = oldC.Spec.ControlPlaneLoadBalancer.DeepCopy()
	}
	if oldC.Spec.ControlPlaneLoadBalancer == nil {
		// If old scheme was nil, the only value accepted here is the default value: internet-facing
		if newLoadBalancer.Scheme != nil && newLoadBalancer.Scheme.String() != ELBSchemeInternetFacing.String() {
			allErrs = append(allErrs,
				field.Invalid(field.NewPath("spec", "controlPlaneLoadBalancer", "scheme"),
					r.Spec.ControlPlaneLoadBalancer.Scheme, "field is immutable, default value was set to internet-facing"),
			)
		}
	} else {
		// If old scheme was not nil, the new scheme should be the same.
		if !cmp.Equal(existingLoadBalancer.Scheme, newLoadBalancer.Scheme) {
			allErrs = append(allErrs,
				field.Invalid(field.NewPath("spec", "controlPlaneLoadBalancer", "scheme"),
					r.Spec.ControlPlaneLoadBalancer.Scheme, "field is immutable"),
			)
		}
		// The name must be defined when the AWSCluster is created. If it is not defined,
		// then the controller generates a default name at runtime, but does not store it,
		// so the name remains nil. In either case, the name cannot be changed.
		if !cmp.Equal(existingLoadBalancer.Name, newLoadBalancer.Name) {
			allErrs = append(allErrs,
				field.Invalid(field.NewPath("spec", "controlPlaneLoadBalancer", "name"),
					r.Spec.ControlPlaneLoadBalancer.Name, "field is immutable"),
			)
		}
	}

	// Block the update for Protocol :
	// - if it was not set in old spec but added in new spec
	// - if it was set in old spec but changed in new spec
	if !cmp.Equal(newLoadBalancer.HealthCheckProtocol, existingLoadBalancer.HealthCheckProtocol) {
		allErrs = append(allErrs,
			field.Invalid(field.NewPath("spec", "controlPlaneLoadBalancer", "healthCheckProtocol"),
				newLoadBalancer.HealthCheckProtocol, "field is immutable once set"),
		)
	}

	if !cmp.Equal(oldC.Spec.ControlPlaneEndpoint, clusterv1.APIEndpoint{}) &&
		!cmp.Equal(r.Spec.ControlPlaneEndpoint, oldC.Spec.ControlPlaneEndpoint) {
		allErrs = append(allErrs,
			field.Invalid(field.NewPath("spec", "controlPlaneEndpoint"), r.Spec.ControlPlaneEndpoint, "field is immutable"),
		)
	}

	// Modifying VPC id is not allowed because it will cause a new VPC creation if set to nil.
	if !cmp.Equal(oldC.Spec.NetworkSpec, NetworkSpec{}) &&
		!cmp.Equal(oldC.Spec.NetworkSpec.VPC, VPCSpec{}) &&
		oldC.Spec.NetworkSpec.VPC.ID != "" {
		if cmp.Equal(r.Spec.NetworkSpec, NetworkSpec{}) ||
			cmp.Equal(r.Spec.NetworkSpec.VPC, VPCSpec{}) ||
			oldC.Spec.NetworkSpec.VPC.ID != r.Spec.NetworkSpec.VPC.ID {
			allErrs = append(allErrs,
				field.Invalid(field.NewPath("spec", "network", "vpc", "id"),
					r.Spec.NetworkSpec.VPC.ID, "field cannot be modified once set"))
		}
	}

	// If a identityRef is already set, do not allow removal of it.
	if oldC.Spec.IdentityRef != nil && r.Spec.IdentityRef == nil {
		allErrs = append(allErrs,
			field.Invalid(field.NewPath("spec", "identityRef"),
				r.Spec.IdentityRef, "field cannot be set to nil"),
		)
	}

	if annotations.IsExternallyManaged(oldC) && !annotations.IsExternallyManaged(r) {
		allErrs = append(allErrs,
			field.Invalid(field.NewPath("metadata", "annotations"),
				r.Annotations, "removal of externally managed annotation is not allowed"),
		)
	}

	allErrs = append(allErrs, r.Spec.Bastion.Validate()...)
	allErrs = append(allErrs, r.Spec.AdditionalTags.Validate()...)
	allErrs = append(allErrs, r.Spec.S3Bucket.Validate()...)

	return nil, aggregateObjErrors(r.GroupVersionKind().GroupKind(), r.Name, allErrs)
}

// Default satisfies the defaulting webhook interface.
func (r *AWSCluster) Default() {
	SetObjectDefaults_AWSCluster(r)
}

func (r *AWSCluster) validateGCTasksAnnotation() field.ErrorList {
	var allErrs field.ErrorList

	annotations := r.GetAnnotations()
	if annotations == nil {
		return nil
	}

	if gcTasksAnnotationValue := annotations[ExternalResourceGCTasksAnnotation]; gcTasksAnnotationValue != "" {
		gcTasks := strings.Split(gcTasksAnnotationValue, ",")

		supportedGCTasks := []GCTask{GCTaskLoadBalancer, GCTaskTargetGroup, GCTaskSecurityGroup}

		for _, gcTask := range gcTasks {
			found := false

			for _, supportedGCTask := range supportedGCTasks {
				if gcTask == string(supportedGCTask) {
					found = true
					break
				}
			}

			if !found {
				allErrs = append(allErrs,
					field.Invalid(field.NewPath("metadata", "annotations"),
						r.Annotations,
						fmt.Sprintf("annotation %s contains unsupported GC task %s", ExternalResourceGCTasksAnnotation, gcTask)),
				)
			}
		}
	}

	return allErrs
}

func (r *AWSCluster) validateSSHKeyName() field.ErrorList {
	return validateSSHKeyName(r.Spec.SSHKeyName)
}

func (r *AWSCluster) validateNetwork() field.ErrorList {
	var allErrs field.ErrorList
	if r.Spec.NetworkSpec.VPC.IsIPv6Enabled() {
		allErrs = append(allErrs, field.Invalid(field.NewPath("ipv6"), r.Spec.NetworkSpec.VPC.IPv6, "IPv6 cannot be used with unmanaged clusters at this time."))
	}
	for _, subnet := range r.Spec.NetworkSpec.Subnets {
		if subnet.IsIPv6 || subnet.IPv6CidrBlock != "" {
			allErrs = append(allErrs, field.Invalid(field.NewPath("subnets"), r.Spec.NetworkSpec.Subnets, "IPv6 cannot be used with unmanaged clusters at this time."))
		}
	}

	if r.Spec.NetworkSpec.VPC.CidrBlock != "" && r.Spec.NetworkSpec.VPC.IPAMPool != nil {
		allErrs = append(allErrs, field.Invalid(field.NewPath("cidrBlock"), r.Spec.NetworkSpec.VPC.CidrBlock, "cidrBlock and ipamPool cannot be used together"))
	}

	if r.Spec.NetworkSpec.VPC.IPAMPool != nil && r.Spec.NetworkSpec.VPC.IPAMPool.ID == "" && r.Spec.NetworkSpec.VPC.IPAMPool.Name == "" {
		allErrs = append(allErrs, field.Invalid(field.NewPath("ipamPool"), r.Spec.NetworkSpec.VPC.IPAMPool, "ipamPool must have either id or name"))
	}

	for _, rule := range r.Spec.NetworkSpec.AdditionalControlPlaneIngressRules {
		if (rule.CidrBlocks != nil || rule.IPv6CidrBlocks != nil) && (rule.SourceSecurityGroupIDs != nil || rule.SourceSecurityGroupRoles != nil) {
			allErrs = append(allErrs, field.Invalid(field.NewPath("additionalControlPlaneIngressRules"), r.Spec.NetworkSpec.AdditionalControlPlaneIngressRules, "CIDR blocks and security group IDs or security group roles cannot be used together"))
		}
	}
	return allErrs
}

func (r *AWSCluster) validateControlPlaneLB() field.ErrorList {
	var allErrs field.ErrorList

	if r.Spec.ControlPlaneLoadBalancer == nil {
		return allErrs
	}

	// Additional listeners are only supported for NLBs.
	if len(r.Spec.ControlPlaneLoadBalancer.AdditionalListeners) > 0 {
		if r.Spec.ControlPlaneLoadBalancer.LoadBalancerType != LoadBalancerTypeNLB {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec", "controlPlaneLoadBalancer", "additionalNetworkListeners"), r.Spec.ControlPlaneLoadBalancer.AdditionalListeners, "additional listeners are only supported for NLB load balancers"))
		}
	}

	for _, rule := range r.Spec.ControlPlaneLoadBalancer.IngressRules {
		if (rule.CidrBlocks != nil || rule.IPv6CidrBlocks != nil) && (rule.SourceSecurityGroupIDs != nil || rule.SourceSecurityGroupRoles != nil) {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec", "controlPlaneLoadBalancer", "ingressRules"), r.Spec.ControlPlaneLoadBalancer.IngressRules, "CIDR blocks and security group IDs or security group roles cannot be used together"))
		}
	}

	return allErrs
}
