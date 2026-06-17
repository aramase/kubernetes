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
	"slices"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	kubeapiservertesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/pkg/kubeapiserver/admission/exclusion"
	"k8s.io/kubernetes/test/integration/framework"
)

func TestExcludedResources(t *testing.T) {
	t.Run("parity with validating and mutating admission policy exclusions", func(t *testing.T) {
		server := kubeapiservertesting.StartTestServerOrDie(t, nil, []string{"--runtime-config=api/all=true"}, framework.SharedEtcd())
		defer server.TearDownFn()

		discoveryClient, err := discovery.NewDiscoveryClientForConfig(server.ClientConfig)
		if err != nil {
			t.Fatalf("failed to create discovery client: %v", err)
		}

		resources := discoverExcludedWebhookResources(t, discoveryClient)
		actual := sets.New[schema.GroupResource]()
		for _, resource := range resources {
			actual.Insert(resource.gvr.GroupResource())
		}

		expected := sets.New(exclusion.Excluded()...)
		if missing := expected.Difference(actual); missing.Len() > 0 {
			t.Fatalf("webhook exclusion list is missing resources present in VAP/MAP exclusions:\n%s", formatGroupResources(missing.UnsortedList()))
		}
		if extra := actual.Difference(expected); extra.Len() > 0 {
			t.Fatalf("webhook exclusion parity picked up unexpected resources:\n%s", formatGroupResources(extra.UnsortedList()))
		}
	})

	for _, tc := range []struct {
		name               string
		featureEnabled     bool
		expectedCallsDelta int64
	}{
		{
			name:               "gate enabled skips excluded resources",
			featureEnabled:     true,
			expectedCallsDelta: 0,
		},
		{
			name:               "gate disabled dispatches excluded resources",
			featureEnabled:     false,
			expectedCallsDelta: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ExcludeAdmissionWebhookVirtualResources, tc.featureEnabled)

			server := kubeapiservertesting.StartTestServerOrDie(t, nil, []string{"--disable-admission-plugins=ServiceAccount"}, framework.SharedEtcd())
			defer server.TearDownFn()

			client, err := clientset.NewForConfig(rest.CopyConfig(server.ClientConfig))
			if err != nil {
				t.Fatalf("failed to create clientset: %v", err)
			}
			dynamicClient, err := dynamic.NewForConfig(rest.CopyConfig(server.ClientConfig))
			if err != nil {
				t.Fatalf("failed to create dynamic client: %v", err)
			}
			discoveryClient, err := discovery.NewDiscoveryClientForConfig(rest.CopyConfig(server.ClientConfig))
			if err != nil {
				t.Fatalf("failed to create discovery client: %v", err)
			}

			if _, err := client.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: testNamespace},
			}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
				t.Fatalf("failed to create test namespace: %v", err)
			}

			webhookServer, caBundle, requestCount := createStaticTestWebhookServer(t)
			defer webhookServer.Close()

			if err := createExcludedValidationWebhook(client, webhookServer.URL, caBundle); err != nil {
				t.Fatalf("failed to create validating webhook config: %v", err)
			}
			if err := createExcludedMutationWebhook(client, webhookServer.URL, caBundle); err != nil {
				t.Fatalf("failed to create mutating webhook config: %v", err)
			}

			waitForWebhookDispatch(t, client, requestCount)

			for _, resource := range discoverExcludedWebhookResources(t, discoveryClient) {
				before := requestCount.Load()
				if _, err := createOrGetResource(dynamicClient, resource.gvr, resource.resource); err != nil {
					t.Fatalf("failed to create resource %s: %v", resource.gvr, err)
				}
				after := requestCount.Load()
				if delta := after - before; delta != tc.expectedCallsDelta {
					t.Fatalf("unexpected webhook dispatch count for %s: got %d, want %d", resource.gvr, delta, tc.expectedCallsDelta)
				}
			}
		})
	}
}

type discoveredExcludedResource struct {
	gvr      schema.GroupVersionResource
	resource metav1.APIResource
}

func discoverExcludedWebhookResources(t *testing.T, discoveryClient *discovery.DiscoveryClient) []discoveredExcludedResource {
	t.Helper()

	_, resourceLists, _, err := discoveryClient.GroupsAndMaybeResources()
	if err != nil {
		t.Fatalf("failed to discover resources: %v", err)
	}

	expected := sets.New(exclusion.Excluded()...)
	discovered := map[schema.GroupResource]discoveredExcludedResource{}
	interestedVerbCombinations := []metav1.Verbs{
		{"create"},
		{"create", "get"},
	}

	for _, resourceList := range resourceLists {
		gv, err := schema.ParseGroupVersion(resourceList.GroupVersion)
		if err != nil {
			t.Fatalf("failed to parse group version %q: %v", resourceList.GroupVersion, err)
		}

		for _, resource := range resourceList.APIResources {
			slices.Sort(resource.Verbs)
			for _, verbs := range interestedVerbCombinations {
				if !slices.Equal(resource.Verbs, verbs) {
					continue
				}

				gvr := gv.WithResource(resource.Name)
				gr := gvr.GroupResource()
				if !expected.Has(gr) {
					break
				}
				if _, exists := discovered[gr]; !exists {
					discovered[gr] = discoveredExcludedResource{gvr: gvr, resource: resource}
				}
				break
			}
		}
	}

	result := make([]discoveredExcludedResource, 0, len(discovered))
	for _, resource := range discovered {
		result = append(result, resource)
	}
	slices.SortFunc(result, func(a, b discoveredExcludedResource) int {
		return strings.Compare(a.gvr.String(), b.gvr.String())
	})
	return result
}

func createExcludedValidationWebhook(client clientset.Interface, endpoint string, caBundle []byte) error {
	fail := admissionregistrationv1.Fail
	none := admissionregistrationv1.SideEffectClassNone
	_, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(context.Background(), &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "excluded-resources-validating"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name: "excluded-resources-validating.k8s.io",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				URL:      &endpoint,
				CABundle: caBundle,
			},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{"*", "*/*"},
				},
			}},
			FailurePolicy:           &fail,
			AdmissionReviewVersions: []string{"v1"},
			SideEffects:             &none,
		}},
	}, metav1.CreateOptions{})
	return err
}

func createExcludedMutationWebhook(client clientset.Interface, endpoint string, caBundle []byte) error {
	fail := admissionregistrationv1.Fail
	none := admissionregistrationv1.SideEffectClassNone
	_, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(context.Background(), &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "excluded-resources-mutating"},
		Webhooks: []admissionregistrationv1.MutatingWebhook{{
			Name: "excluded-resources-mutating.k8s.io",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				URL:      &endpoint,
				CABundle: caBundle,
			},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{"*", "*/*"},
				},
			}},
			FailurePolicy:           &fail,
			AdmissionReviewVersions: []string{"v1"},
			SideEffects:             &none,
		}},
	}, metav1.CreateOptions{})
	return err
}

func waitForWebhookDispatch(t *testing.T, client clientset.Interface, requestCount interface{ Load() int64 }) {
	t.Helper()

	countBefore := requestCount.Load()
	var lastErr error
	err := wait.PollUntilContextTimeout(t.Context(), 100*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		cmName := fmt.Sprintf("excluded-resources-probe-%d", requestCount.Load())
		cm, err := client.CoreV1().ConfigMaps(testNamespace).Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: testNamespace},
		}, metav1.CreateOptions{})
		if err != nil {
			lastErr = err
			return false, nil
		}
		_ = client.CoreV1().ConfigMaps(testNamespace).Delete(ctx, cm.Name, metav1.DeleteOptions{})
		return requestCount.Load()-countBefore >= 2, nil
	})
	if err != nil {
		t.Fatalf("timed out waiting for probe request to hit both webhooks: %v (last error: %v)", err, lastErr)
	}
}

func formatGroupResources(resources []schema.GroupResource) string {
	lines := make([]string, 0, len(resources))
	for _, resource := range resources {
		lines = append(lines, fmt.Sprintf("%#v,", resource))
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}
