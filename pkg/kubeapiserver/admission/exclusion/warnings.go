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

package exclusion

import (
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ExplicitlyNamedExcludedResources returns excluded resources whose group and resource
// are explicitly listed in the provided rule fields.
func ExplicitlyNamedExcludedResources(apiGroups, resources []string) []schema.GroupResource {
	var matched []schema.GroupResource
	for _, excludedResource := range excluded {
		if !slices.Contains(apiGroups, excludedResource.Group) {
			continue
		}
		if !slices.Contains(resources, excludedResource.Resource) {
			continue
		}
		matched = append(matched, excludedResource)
	}
	return matched
}

func WebhookConfigurationWarning(webhookName, kind, configurationName string, resource schema.GroupResource) string {
	return fmt.Sprintf(`webhook %q in %s %q matches excluded virtual resource %s/%s; this resource will not be sent to webhooks when the ExcludeAdmissionWebhookVirtualResources feature gate is enabled (default in v1.37)`, webhookName, kind, configurationName, resource.Group, resource.Resource)
}
