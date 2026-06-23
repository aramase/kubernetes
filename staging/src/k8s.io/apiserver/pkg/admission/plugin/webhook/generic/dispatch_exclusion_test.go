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

package generic

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/webhook"
)

type recordingDispatcher struct {
	called bool
}

func (d *recordingDispatcher) Dispatch(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces, hooks []webhook.WebhookAccessor) error {
	d.called = true
	return nil
}

type syncedWebhookSource struct{}

func (syncedWebhookSource) Webhooks() []webhook.WebhookAccessor { return nil }
func (syncedWebhookSource) HasSynced() bool                     { return true }

func attributesForResource(gvr schema.GroupVersionResource) admission.Attributes {
	gvk := schema.GroupVersionKind{Group: gvr.Group, Version: gvr.Version, Kind: "Test"}
	return admission.NewAttributesRecord(nil, nil, gvk, "", "name", gvr, "", admission.Create, &metav1.CreateOptions{}, false, nil)
}

// TestDispatchExcludedVirtualResources verifies that webhook admission skips dispatch
// for the injected excluded virtual resources only when the exclusion is enabled.
func TestDispatchExcludedVirtualResources(t *testing.T) {
	excluded := []schema.GroupResource{
		{Group: "authentication.k8s.io", Resource: "tokenreviews"},
		{Group: "authorization.k8s.io", Resource: "subjectaccessreviews"},
	}
	sar := schema.GroupVersionResource{Group: "authorization.k8s.io", Version: "v1", Resource: "subjectaccessreviews"}
	pods := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	testcases := []struct {
		name              string
		excludeEnabled    bool
		resource          schema.GroupVersionResource
		wantDispatchCalls bool
	}{
		{
			name:              "exclusion enabled, excluded resource is not dispatched",
			excludeEnabled:    true,
			resource:          sar,
			wantDispatchCalls: false,
		},
		{
			name:              "exclusion enabled, non-excluded resource is dispatched",
			excludeEnabled:    true,
			resource:          pods,
			wantDispatchCalls: true,
		},
		{
			name:              "exclusion disabled, excluded resource is dispatched",
			excludeEnabled:    false,
			resource:          sar,
			wantDispatchCalls: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			d := &recordingDispatcher{}
			a := &Webhook{
				Handler:                 admission.NewHandler(admission.Create),
				hookSource:              syncedWebhookSource{},
				dispatcher:              d,
				excludedResources:       sets.New(excluded...),
				excludeVirtualResources: tc.excludeEnabled,
			}

			if err := a.Dispatch(context.Background(), attributesForResource(tc.resource), nil); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.called != tc.wantDispatchCalls {
				t.Errorf("dispatcher called = %v, want %v", d.called, tc.wantDispatchCalls)
			}
		})
	}
}

// TestSetExcludedAdmissionResources verifies the initializer accessor populates the set.
func TestSetExcludedAdmissionResources(t *testing.T) {
	a := &Webhook{}
	excluded := []schema.GroupResource{
		{Group: "authentication.k8s.io", Resource: "tokenreviews"},
		{Group: "authorization.k8s.io", Resource: "subjectaccessreviews"},
	}
	a.SetExcludedAdmissionResources(excluded)
	for _, gr := range excluded {
		if !a.excludedResources.Has(gr) {
			t.Errorf("expected excluded resources to contain %v", gr)
		}
	}
}
