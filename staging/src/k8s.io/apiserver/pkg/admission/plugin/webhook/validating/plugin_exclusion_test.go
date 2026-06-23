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

package validating

import (
	"context"
	"net/url"
	"testing"

	registrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/testcerts"
	webhooktesting "k8s.io/apiserver/pkg/admission/plugin/webhook/testing"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

// TestValidateExcludedVirtualResources verifies that ValidatingAdmissionWebhook skips dispatch
// for resources in the injected excluded set only when the
// ExcludeAdmissionWebhookVirtualResources feature gate is enabled.
func TestValidateExcludedVirtualResources(t *testing.T) {
	testServer := webhooktesting.NewTestServer(t)
	testServer.StartTLS()
	defer testServer.Close()

	serverURL, err := url.ParseRequestURI(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}

	objectInterfaces := webhooktesting.NewObjectInterfacesForTest()
	stopCh := make(chan struct{})
	defer close(stopCh)

	disallowURL := testServer.URL + "/disallow"
	sideEffectsNone := registrationv1.SideEffectClassNone
	disallowWebhook := []registrationv1.ValidatingWebhook{{
		Name:         "disallow.example.com",
		ClientConfig: registrationv1.WebhookClientConfig{URL: &disallowURL, CABundle: testcerts.CACert},
		Rules: []registrationv1.RuleWithOperations{{
			Operations: []registrationv1.OperationType{registrationv1.OperationAll},
			Rule:       registrationv1.Rule{APIGroups: []string{"*"}, APIVersions: []string{"*"}, Resources: []string{"*/*"}},
		}},
		NamespaceSelector:       &metav1.LabelSelector{},
		ObjectSelector:          &metav1.LabelSelector{},
		AdmissionReviewVersions: []string{"v1beta1"},
		SideEffects:             &sideEffectsNone,
	}}

	// webhooktesting.NewAttribute builds a Pod attribute whose resource is the singular
	// "pod". We inject that into the excluded set to drive the skip path, and a
	// non-matching resource to prove set membership is what gates the skip.
	pod := schema.GroupResource{Group: "", Resource: "pod"}
	sar := schema.GroupResource{Group: "authorization.k8s.io", Resource: "subjectaccessreviews"}

	testcases := []struct {
		name        string
		gateEnabled bool
		excluded    []schema.GroupResource
		expectAllow bool
	}{
		{
			name:        "gate enabled, request resource excluded, webhook skipped",
			gateEnabled: true,
			excluded:    []schema.GroupResource{pod},
			expectAllow: true,
		},
		{
			name:        "gate disabled, request resource excluded, webhook dispatched",
			gateEnabled: false,
			excluded:    []schema.GroupResource{pod},
			expectAllow: false,
		},
		{
			name:        "gate enabled, request resource not excluded, webhook dispatched",
			gateEnabled: true,
			excluded:    []schema.GroupResource{sar},
			expectAllow: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ExcludeAdmissionWebhookVirtualResources, tc.gateEnabled)

			wh, err := NewValidatingAdmissionWebhook(nil)
			if err != nil {
				t.Fatalf("failed to create validating webhook: %v", err)
			}

			ns := "webhook-test"
			client, informer := webhooktesting.NewFakeValidatingDataSource(ns, disallowWebhook, stopCh)
			wh.SetAuthenticationInfoResolverWrapper(webhooktesting.Wrapper(webhooktesting.NewAuthenticationInfoResolver(new(int32))))
			wh.SetServiceResolver(webhooktesting.NewServiceResolver(*serverURL))
			wh.SetExternalKubeClientSet(client)
			wh.SetExternalKubeInformerFactory(informer)
			wh.SetExcludedAdmissionResources(tc.excluded)

			informer.Start(stopCh)
			informer.WaitForCacheSync(stopCh)

			if err = wh.ValidateInitialization(); err != nil {
				t.Fatalf("failed to validate initialization: %v", err)
			}

			attr := webhooktesting.NewAttribute(ns, nil, false)
			err = wh.Validate(context.TODO(), attr, objectInterfaces)
			if tc.expectAllow != (err == nil) {
				t.Errorf("expected allow=%v, but got err=%v", tc.expectAllow, err)
			}
		})
	}
}
