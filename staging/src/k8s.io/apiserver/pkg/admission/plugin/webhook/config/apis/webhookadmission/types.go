/*
Copyright 2017 The Kubernetes Authors.

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

package webhookadmission

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WebhookAdmission provides configuration for the webhook admission controller.
type WebhookAdmission struct {
	metav1.TypeMeta

	// KubeConfigFile is the path to the kubeconfig file.
	KubeConfigFile string

	// StaticManifestsDir is the path to a directory containing static webhook
	// configurations to be loaded at startup. Files with extensions .yaml,
	// .yml, and .json are read. Only admissionregistration.k8s.io/v1
	// ValidatingWebhookConfiguration and MutatingWebhookConfiguration
	// resources are supported.
	// Using this field requires the ManifestBasedAdmissionControlConfig
	// feature gate to be enabled.
	// +optional
	StaticManifestsDir string

	// StaticOrder determines where the webhooks loaded from StaticManifestsDir are
	// placed relative to the webhooks read from the API. Mutating webhooks are
	// dispatched sequentially, so this controls the order in which they observe and
	// mutate an object.
	// Empty means StaticFirst, which is the only behavior available before v1.38.
	// May only be set when StaticManifestsDir is set.
	// This field is only honored by the MutatingAdmissionWebhook plugin. Setting it to
	// any value other than StaticFirst on the ValidatingAdmissionWebhook plugin is a
	// configuration error, because validating webhooks are dispatched in parallel
	// against the same object and cannot have ordering dependencies.
	// Using this field requires the ManifestBasedAdmissionControlConfig feature gate
	// to be enabled.
	// +optional
	StaticOrder StaticOrder
}

// StaticOrder determines where manifest-based webhooks are placed relative to
// webhooks read from the API.
type StaticOrder string

const (
	// StaticFirst runs manifest-based webhooks before all API-based webhooks.
	StaticFirst StaticOrder = "StaticFirst"
	// StaticLast runs manifest-based webhooks after all API-based webhooks.
	StaticLast StaticOrder = "StaticLast"
	// ByName interleaves manifest-based and API-based webhooks, stably sorting them
	// together by the name of the webhook configuration that contains them. This is
	// how API-based webhooks are already ordered relative to each other, so a
	// manifest-based configuration keeps the position of the API-based configuration
	// it replaces when it is named after it.
	ByName StaticOrder = "ByName"
)
