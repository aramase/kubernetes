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

package admissionwebhook

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	kubeapiservertesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/pkg/kubeapiserver/admission/exclusion"
	"k8s.io/kubernetes/test/integration/framework"
	"k8s.io/utils/ptr"
)

// TestWebhookExcludedVirtualResources verifies that ValidatingAdmissionWebhook and
// MutatingAdmissionWebhook skip dispatch for the non-persisted auth/authz virtual
// resources in exclusion.Excluded() when the ExcludeAdmissionWebhookVirtualResources
// feature gate is enabled, matching ValidatingAdmissionPolicy and MutatingAdmissionPolicy.
//
// This mirrors the parity intent of test/integration/apiserver/cel/excludedresources_test.go.
func TestWebhookExcludedVirtualResources(t *testing.T) {
	testcases := []struct {
		name           string
		gateEnabled    bool
		wantDispatched bool
	}{
		{
			name:           "gate enabled, excluded virtual resources are not dispatched to webhooks",
			gateEnabled:    true,
			wantDispatched: false,
		},
		{
			name:           "gate disabled, excluded virtual resources are dispatched to webhooks",
			gateEnabled:    false,
			wantDispatched: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ExcludeAdmissionWebhookVirtualResources, tc.gateEnabled)
			ctx := t.Context()

			server := kubeapiservertesting.StartTestServerOrDie(t, nil, []string{
				"--disable-admission-plugins=ServiceAccount",
			}, framework.SharedEtcd())
			defer server.TearDownFn()

			client, err := clientset.NewForConfig(rest.CopyConfig(server.ClientConfig))
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			// Each webhook configuration has a control webhook (intercepting configmaps,
			// which are never excluded) used to detect when the configuration becomes
			// active, and an excluded webhook (intercepting exclusion.Excluded()) whose
			// invocation counter is the assertion target.
			ctrlValidating, _, ctrlValidatingCount := createStaticTestWebhookServer(t)
			defer ctrlValidating.Close()
			exclValidating, _, exclValidatingCount := createStaticTestWebhookServer(t)
			defer exclValidating.Close()
			ctrlMutating, _, ctrlMutatingCount := createStaticTestWebhookServer(t)
			defer ctrlMutating.Close()
			exclMutating, _, exclMutatingCount := createStaticTestWebhookServer(t)
			defer exclMutating.Close()

			registerValidatingExclusionWebhook(ctx, t, client, ctrlValidating.URL, exclValidating.URL)
			registerMutatingExclusionWebhook(ctx, t, client, ctrlMutating.URL, exclMutating.URL)

			// Wait until both configurations are active by creating configmaps (a
			// non-excluded resource) until both control webhooks observe traffic.
			waitForWebhooksActive(ctx, t, client, ctrlValidatingCount, ctrlMutatingCount)

			// Reset the excluded-webhook counters so only the virtual resource requests
			// below are measured. Admission webhooks are invoked synchronously during the
			// create request, so the counters are accurate immediately afterwards.
			exclValidatingCount.Store(0)
			exclMutatingCount.Store(0)

			createVirtualResources(ctx, t, client)

			gotValidating := exclValidatingCount.Load()
			gotMutating := exclMutatingCount.Load()
			if tc.wantDispatched {
				if gotValidating == 0 {
					t.Errorf("expected validating webhook to be dispatched for excluded virtual resources, but it was not")
				}
				if gotMutating == 0 {
					t.Errorf("expected mutating webhook to be dispatched for excluded virtual resources, but it was not")
				}
				return
			}
			if gotValidating != 0 {
				t.Errorf("expected validating webhook to be skipped for excluded virtual resources, but it was dispatched %d time(s)", gotValidating)
			}
			if gotMutating != 0 {
				t.Errorf("expected mutating webhook to be skipped for excluded virtual resources, but it was dispatched %d time(s)", gotMutating)
			}
		})
	}
}

// excludedResourceRules builds webhook rules matching every GroupResource in
// exclusion.Excluded(), so the test stays in parity with the canonical list.
func excludedResourceRules() []admissionregistrationv1.RuleWithOperations {
	var rules []admissionregistrationv1.RuleWithOperations
	for _, gr := range exclusion.Excluded() {
		rules = append(rules, admissionregistrationv1.RuleWithOperations{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{gr.Group},
				APIVersions: []string{"*"},
				Resources:   []string{gr.Resource},
			},
		})
	}
	return rules
}

func configmapRules() []admissionregistrationv1.RuleWithOperations {
	return []admissionregistrationv1.RuleWithOperations{{
		Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
		Rule: admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"configmaps"},
		},
	}}
}

func registerValidatingExclusionWebhook(ctx context.Context, t *testing.T, client clientset.Interface, controlURL, excludedURL string) {
	t.Helper()
	cfg := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "exclusion.integration.test.validating"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			newValidatingWebhook("control.exclusion.integration.test", controlURL, configmapRules()),
			newValidatingWebhook("excluded.exclusion.integration.test", excludedURL, excludedResourceRules()),
		},
	}
	if _, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, cfg, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create validating webhook configuration: %v", err)
	}
	t.Cleanup(func() {
		_ = client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(context.Background(), cfg.Name, metav1.DeleteOptions{})
	})
}

func registerMutatingExclusionWebhook(ctx context.Context, t *testing.T, client clientset.Interface, controlURL, excludedURL string) {
	t.Helper()
	cfg := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "exclusion.integration.test.mutating"},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			newMutatingWebhook("control.exclusion.integration.test", controlURL, configmapRules()),
			newMutatingWebhook("excluded.exclusion.integration.test", excludedURL, excludedResourceRules()),
		},
	}
	if _, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(ctx, cfg, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create mutating webhook configuration: %v", err)
	}
	t.Cleanup(func() {
		_ = client.AdmissionregistrationV1().MutatingWebhookConfigurations().Delete(context.Background(), cfg.Name, metav1.DeleteOptions{})
	})
}

func newValidatingWebhook(name, url string, rules []admissionregistrationv1.RuleWithOperations) admissionregistrationv1.ValidatingWebhook {
	return admissionregistrationv1.ValidatingWebhook{
		Name:                    name,
		ClientConfig:            admissionregistrationv1.WebhookClientConfig{URL: ptr.To(url), CABundle: localhostCert},
		Rules:                   rules,
		FailurePolicy:           ptr.To(admissionregistrationv1.Ignore),
		MatchPolicy:             ptr.To(admissionregistrationv1.Exact),
		SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
		AdmissionReviewVersions: []string{"v1"},
		TimeoutSeconds:          ptr.To[int32](5),
		NamespaceSelector:       &metav1.LabelSelector{},
		ObjectSelector:          &metav1.LabelSelector{},
	}
}

func newMutatingWebhook(name, url string, rules []admissionregistrationv1.RuleWithOperations) admissionregistrationv1.MutatingWebhook {
	return admissionregistrationv1.MutatingWebhook{
		Name:                    name,
		ClientConfig:            admissionregistrationv1.WebhookClientConfig{URL: ptr.To(url), CABundle: localhostCert},
		Rules:                   rules,
		FailurePolicy:           ptr.To(admissionregistrationv1.Ignore),
		MatchPolicy:             ptr.To(admissionregistrationv1.Exact),
		SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
		AdmissionReviewVersions: []string{"v1"},
		TimeoutSeconds:          ptr.To[int32](5),
		NamespaceSelector:       &metav1.LabelSelector{},
		ObjectSelector:          &metav1.LabelSelector{},
	}
}

// waitForWebhooksActive creates configmaps (a non-excluded resource) until both control
// webhooks observe traffic, confirming both webhook configurations are in effect.
func waitForWebhooksActive(ctx context.Context, t *testing.T, client clientset.Interface, counters ...*atomic.Int64) {
	t.Helper()
	i := 0
	err := wait.PollUntilContextTimeout(ctx, 250*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		i++
		_, err := client.CoreV1().ConfigMaps("default").Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("webhook-exclusion-marker-%d", i)},
		}, metav1.CreateOptions{})
		if err != nil {
			return false, err
		}
		for _, c := range counters {
			if c.Load() == 0 {
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for webhooks to become active: %v", err)
	}
}

// createVirtualResources issues create requests for every excluded auth/authz virtual
// resource. These are non-persisted reviews; the create returns a populated status.
func createVirtualResources(ctx context.Context, t *testing.T, client clientset.Interface) {
	t.Helper()

	resourceAttributes := &authorizationv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods", Namespace: "default"}

	if _, err := client.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{User: "alice", ResourceAttributes: resourceAttributes},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create SubjectAccessReview: %v", err)
	}

	if _, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: resourceAttributes},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create SelfSubjectAccessReview: %v", err)
	}

	if _, err := client.AuthorizationV1().LocalSubjectAccessReviews("default").Create(ctx, &authorizationv1.LocalSubjectAccessReview{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
		Spec:       authorizationv1.SubjectAccessReviewSpec{User: "alice", ResourceAttributes: resourceAttributes},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create LocalSubjectAccessReview: %v", err)
	}

	if _, err := client.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, &authorizationv1.SelfSubjectRulesReview{
		Spec: authorizationv1.SelfSubjectRulesReviewSpec{Namespace: "default"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create SelfSubjectRulesReview: %v", err)
	}

	if _, err := client.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: "not-a-real-token"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create TokenReview: %v", err)
	}

	if _, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create SelfSubjectReview: %v", err)
	}
}
