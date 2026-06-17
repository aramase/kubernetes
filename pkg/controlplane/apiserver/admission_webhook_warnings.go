/*
Copyright The Kubernetes Authors.

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

package apiserver

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/kubernetes/pkg/kubeapiserver/admission/exclusion"
)

func excludedAdmissionWebhookWarnings(validatingConfigs []*admissionregistrationv1.ValidatingWebhookConfiguration, mutatingConfigs []*admissionregistrationv1.MutatingWebhookConfiguration) []string {
	var warnings []string
	for _, configuration := range validatingConfigs {
		warnings = append(warnings, excludedValidatingWebhookWarnings(configuration)...)
	}
	for _, configuration := range mutatingConfigs {
		warnings = append(warnings, excludedMutatingWebhookWarnings(configuration)...)
	}
	return warnings
}

func excludedValidatingWebhookWarnings(configuration *admissionregistrationv1.ValidatingWebhookConfiguration) []string {
	var warnings []string
	for _, webhook := range configuration.Webhooks {
		warnedResources := map[string]struct{}{}
		for _, rule := range webhook.Rules {
			for _, resource := range exclusion.ExplicitlyNamedExcludedResources(rule.APIGroups, rule.Resources) {
				resourceKey := resource.String()
				if _, seen := warnedResources[resourceKey]; seen {
					continue
				}
				warnedResources[resourceKey] = struct{}{}
				warnings = append(warnings, exclusion.WebhookConfigurationWarning(webhook.Name, "ValidatingWebhookConfiguration", configuration.Name, resource))
			}
		}
	}
	return warnings
}

func excludedMutatingWebhookWarnings(configuration *admissionregistrationv1.MutatingWebhookConfiguration) []string {
	var warnings []string
	for _, webhook := range configuration.Webhooks {
		warnedResources := map[string]struct{}{}
		for _, rule := range webhook.Rules {
			for _, resource := range exclusion.ExplicitlyNamedExcludedResources(rule.APIGroups, rule.Resources) {
				resourceKey := resource.String()
				if _, seen := warnedResources[resourceKey]; seen {
					continue
				}
				warnedResources[resourceKey] = struct{}{}
				warnings = append(warnings, exclusion.WebhookConfigurationWarning(webhook.Name, "MutatingWebhookConfiguration", configuration.Name, resource))
			}
		}
	}
	return warnings
}
