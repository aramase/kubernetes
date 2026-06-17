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
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestExcludedAdmissionWebhookWarnings(t *testing.T) {
	warnings := excludedAdmissionWebhookWarnings(
		[]*admissionregistrationv1.ValidatingWebhookConfiguration{{
			ObjectMeta: metav1.ObjectMeta{Name: "validating-config"},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{{
				Name: "validating.example.com",
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"authentication.k8s.io"},
						APIVersions: []string{"v1"},
						Resources:   []string{"tokenreviews"},
					},
				}},
			}},
		}},
		[]*admissionregistrationv1.MutatingWebhookConfiguration{{
			ObjectMeta: metav1.ObjectMeta{Name: "mutating-config"},
			Webhooks: []admissionregistrationv1.MutatingWebhook{{
				Name: "mutating.example.com",
				Rules: []admissionregistrationv1.RuleWithOperations{{
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{"v1"},
						Resources:   []string{"subjectaccessreviews"},
					},
				}},
			}},
		}},
	)

	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}

	expected := `webhook "validating.example.com" in ValidatingWebhookConfiguration "validating-config" matches excluded virtual resource authentication.k8s.io/tokenreviews; this resource will not be sent to webhooks when the ExcludeAdmissionWebhookVirtualResources feature gate is enabled (default in v1.37)`
	if warnings[0] != expected {
		t.Fatalf("expected warning %q, got %q", expected, warnings[0])
	}
}
