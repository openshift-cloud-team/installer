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

package v1beta1

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	maxNodePoolNameLength = 40
)

// log is for logging in this package.
var gcpmanagedmachinepoollog = logf.Log.WithName("gcpmanagedmachinepool-resource")

func (r *GCPManagedMachinePool) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

//+kubebuilder:webhook:path=/mutate-infrastructure-cluster-x-k8s-io-v1beta1-gcpmanagedmachinepool,mutating=true,failurePolicy=fail,sideEffects=None,groups=infrastructure.cluster.x-k8s.io,resources=gcpmanagedmachinepools,verbs=create;update,versions=v1beta1,name=mgcpmanagedmachinepool.kb.io,admissionReviewVersions=v1

var _ webhook.Defaulter = &GCPManagedMachinePool{}

// Default implements webhook.Defaulter so a webhook will be registered for the type.
func (r *GCPManagedMachinePool) Default() {
	gcpmanagedmachinepoollog.Info("default", "name", r.Name)
}

//+kubebuilder:webhook:path=/validate-infrastructure-cluster-x-k8s-io-v1beta1-gcpmanagedmachinepool,mutating=false,failurePolicy=fail,sideEffects=None,groups=infrastructure.cluster.x-k8s.io,resources=gcpmanagedmachinepools,verbs=create;update,versions=v1beta1,name=vgcpmanagedmachinepool.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &GCPManagedMachinePool{}

func (r *GCPManagedMachinePool) validateScaling() field.ErrorList {
	var allErrs field.ErrorList
	if r.Spec.Scaling != nil {
		minField := field.NewPath("spec", "scaling", "minCount")
		maxField := field.NewPath("spec", "scaling", "maxCount")
		min := r.Spec.Scaling.MinCount
		max := r.Spec.Scaling.MaxCount
		if min != nil {
			if *min < 0 {
				allErrs = append(allErrs, field.Invalid(minField, *min, "must be greater or equal zero"))
			}
			if max != nil && *max < *min {
				allErrs = append(allErrs, field.Invalid(maxField, *max, fmt.Sprintf("must be greater than field %s", minField.String())))
			}
		}
	}
	if len(allErrs) == 0 {
		return nil
	}
	return allErrs
}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type.
func (r *GCPManagedMachinePool) ValidateCreate() (admission.Warnings, error) {
	gcpmanagedmachinepoollog.Info("validate create", "name", r.Name)
	var allErrs field.ErrorList

	if len(r.Spec.NodePoolName) > maxNodePoolNameLength {
		allErrs = append(allErrs,
			field.Invalid(field.NewPath("spec", "NodePoolName"),
				r.Spec.NodePoolName, fmt.Sprintf("node pool name cannot have more than %d characters", maxNodePoolNameLength)),
		)
	}

	if errs := r.validateScaling(); errs != nil || len(errs) == 0 {
		allErrs = append(allErrs, errs...)
	}

	if len(allErrs) == 0 {
		return nil, nil
	}

	return nil, apierrors.NewInvalid(GroupVersion.WithKind("GCPManagedMachinePool").GroupKind(), r.Name, allErrs)
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type.
func (r *GCPManagedMachinePool) ValidateUpdate(oldRaw runtime.Object) (admission.Warnings, error) {
	gcpmanagedmachinepoollog.Info("validate update", "name", r.Name)
	var allErrs field.ErrorList
	old := oldRaw.(*GCPManagedMachinePool)

	if !cmp.Equal(r.Spec.NodePoolName, old.Spec.NodePoolName) {
		allErrs = append(allErrs,
			field.Invalid(field.NewPath("spec", "NodePoolName"),
				r.Spec.NodePoolName, "field is immutable"),
		)
	}

	if errs := r.validateScaling(); errs != nil || len(errs) == 0 {
		allErrs = append(allErrs, errs...)
	}

	if len(allErrs) == 0 {
		return nil, nil
	}

	return nil, apierrors.NewInvalid(GroupVersion.WithKind("GCPManagedMachinePool").GroupKind(), r.Name, allErrs)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type.
func (r *GCPManagedMachinePool) ValidateDelete() (admission.Warnings, error) {
	gcpmanagedmachinepoollog.Info("validate delete", "name", r.Name)

	return nil, nil
}
