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

package validating

import (
	"context"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	admissioninitializer "k8s.io/apiserver/pkg/admission/initializer"
	admissionmetrics "k8s.io/apiserver/pkg/admission/metrics"
	"k8s.io/apiserver/pkg/admission/plugin/webhook"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/generic"
	webhooktesting "k8s.io/apiserver/pkg/admission/plugin/webhook/testing"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/component-base/metrics/testutil"
	controlplaneadmission "k8s.io/kubernetes/pkg/controlplane/apiserver/admission"
	clocktesting "k8s.io/utils/clock/testing"
)

// BenchmarkValidate tests that ValidatingWebhook#Validate works as expected
func BenchmarkValidate(b *testing.B) {
	testServerURL := os.Getenv("WEBHOOK_TEST_SERVER_URL")
	if len(testServerURL) == 0 {
		b.Log("warning, WEBHOOK_TEST_SERVER_URL not set, starting in-process server, benchmarks will include webhook cost.")
		b.Log("to run a standalone server, run:")
		b.Log("go run k8s.io/apiserver/pkg/admission/plugin/webhook/testing/main/main.go")
		testServer := webhooktesting.NewTestServer(b)
		testServer.StartTLS()
		defer testServer.Close()
		testServerURL = testServer.URL
	}

	objectInterfaces := webhooktesting.NewObjectInterfacesForTest()

	serverURL, err := url.ParseRequestURI(testServerURL)
	if err != nil {
		b.Fatalf("this should never happen? %v", err)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	for _, tt := range webhooktesting.NewNonMutatingTestCases(serverURL) {
		// For now, skip failure cases or tests that explicitly skip benchmarking
		if !tt.ExpectAllow || tt.SkipBenchmark {
			continue
		}

		b.Run(tt.Name, func(b *testing.B) {
			wh, err := NewValidatingAdmissionWebhook(nil)
			if err != nil {
				b.Errorf("%s: failed to create validating webhook: %v", tt.Name, err)
				return
			}

			ns := "webhook-test"
			client, informer := webhooktesting.NewFakeValidatingDataSource(ns, tt.Webhooks, stopCh)

			wh.SetAuthenticationInfoResolverWrapper(webhooktesting.Wrapper(webhooktesting.NewAuthenticationInfoResolver(new(int32))))
			wh.SetServiceResolver(webhooktesting.NewServiceResolver(*serverURL))
			wh.SetExternalKubeClientSet(client)
			wh.SetExternalKubeInformerFactory(informer)

			informer.Start(stopCh)
			informer.WaitForCacheSync(stopCh)

			if err = wh.ValidateInitialization(); err != nil {
				b.Errorf("%s: failed to validate initialization: %v", tt.Name, err)
				return
			}

			attr := webhooktesting.NewAttribute(ns, nil, tt.IsDryRun)

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					wh.Validate(context.TODO(), attr, objectInterfaces)
				}
			})
		})
	}
}

// TestValidate tests that ValidatingWebhook#Validate works as expected
func TestValidate(t *testing.T) {
	testServer := webhooktesting.NewTestServer(t)
	testServer.StartTLS()
	defer testServer.Close()

	objectInterfaces := webhooktesting.NewObjectInterfacesForTest()

	serverURL, err := url.ParseRequestURI(testServer.URL)
	if err != nil {
		t.Fatalf("this should never happen? %v", err)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	for _, tt := range webhooktesting.NewNonMutatingTestCases(serverURL) {
		wh, err := NewValidatingAdmissionWebhook(nil)
		if err != nil {
			t.Errorf("%s: failed to create validating webhook: %v", tt.Name, err)
			continue
		}

		ns := "webhook-test"
		client, informer := webhooktesting.NewFakeValidatingDataSource(ns, tt.Webhooks, stopCh)

		wh.SetAuthenticationInfoResolverWrapper(webhooktesting.Wrapper(webhooktesting.NewAuthenticationInfoResolver(new(int32))))
		wh.SetServiceResolver(webhooktesting.NewServiceResolver(*serverURL))
		wh.SetExternalKubeClientSet(client)
		wh.SetExternalKubeInformerFactory(informer)

		informer.Start(stopCh)
		informer.WaitForCacheSync(stopCh)

		if err = wh.ValidateInitialization(); err != nil {
			t.Errorf("%s: failed to validate initialization: %v", tt.Name, err)
			continue
		}

		if len(tt.ExpectRejectionMetrics) > 0 {
			admissionmetrics.Metrics.WebhookRejectionGathererForTest().Reset()
		}

		attr := webhooktesting.NewAttribute(ns, nil, tt.IsDryRun)
		err = wh.Validate(context.TODO(), attr, objectInterfaces)
		if tt.ExpectAllow != (err == nil) {
			t.Errorf("%s: expected allowed=%v, but got err=%v", tt.Name, tt.ExpectAllow, err)
		}
		// ErrWebhookRejected is not an error for our purposes
		if tt.ErrorContains != "" {
			if err == nil || !strings.Contains(err.Error(), tt.ErrorContains) {
				t.Errorf("%s: expected an error saying %q, but got %v", tt.Name, tt.ErrorContains, err)
			}
		}
		if _, isStatusErr := err.(*errors.StatusError); err != nil && !isStatusErr {
			t.Errorf("%s: expected a StatusError, got %T", tt.Name, err)
		}
		if len(tt.ExpectRejectionMetrics) > 0 {
			expectedMetrics := `
# HELP apiserver_admission_webhook_rejection_count [ALPHA] Admission webhook rejection count, identified by name and broken out for each admission type (validating or admit) and operation. Additional labels specify an error type (calling_webhook_error or apiserver_internal_error if an error occurred; no_error otherwise) and optionally a non-zero rejection code if the webhook rejects the request with an HTTP status code (honored by the apiserver when the code is greater or equal to 400). Codes greater than 600 are truncated to 600, to keep the metrics cardinality bounded.
# TYPE apiserver_admission_webhook_rejection_count counter
` + tt.ExpectRejectionMetrics + "\n"
			if err := testutil.CollectAndCompare(admissionmetrics.Metrics.WebhookRejectionGathererForTest(), strings.NewReader(expectedMetrics), "apiserver_admission_webhook_rejection_count"); err != nil {
				t.Errorf("unexpected collecting result:\n%s", err)
			}
		}
		fakeAttr, ok := attr.(*webhooktesting.FakeAttributes)
		if !ok {
			t.Errorf("Unexpected error, failed to convert attr to webhooktesting.FakeAttributes")
			continue
		}
		if len(tt.ExpectAnnotations) == 0 {
			assert.Empty(t, fakeAttr.GetAnnotations(auditinternal.LevelMetadata), tt.Name+": annotations not set as expected.")
		} else {
			assert.Equal(t, tt.ExpectAnnotations, fakeAttr.GetAnnotations(auditinternal.LevelMetadata), tt.Name+": annotations not set as expected.")
		}
	}
}

// TestValidateCachedClient tests that ValidatingWebhook#Validate should cache restClient
func TestValidateCachedClient(t *testing.T) {
	testServer := webhooktesting.NewTestServer(t)
	testServer.StartTLS()
	defer testServer.Close()
	serverURL, err := url.ParseRequestURI(testServer.URL)
	if err != nil {
		t.Fatalf("this should never happen? %v", err)
	}

	objectInterfaces := webhooktesting.NewObjectInterfacesForTest()

	stopCh := make(chan struct{})
	defer close(stopCh)

	wh, err := NewValidatingAdmissionWebhook(nil)
	if err != nil {
		t.Fatalf("Failed to create validating webhook: %v", err)
	}
	wh.SetServiceResolver(webhooktesting.NewServiceResolver(*serverURL))

	for _, tt := range webhooktesting.NewCachedClientTestcases(serverURL) {
		ns := "webhook-test"
		client, informer := webhooktesting.NewFakeValidatingDataSource(ns, tt.Webhooks, stopCh)

		// override the webhook source. The client cache will stay the same.
		cacheMisses := new(int32)
		wh.SetAuthenticationInfoResolverWrapper(webhooktesting.Wrapper(webhooktesting.NewAuthenticationInfoResolver(cacheMisses)))
		wh.SetExternalKubeClientSet(client)
		wh.SetExternalKubeInformerFactory(informer)

		informer.Start(stopCh)
		informer.WaitForCacheSync(stopCh)

		if err = wh.ValidateInitialization(); err != nil {
			t.Errorf("%s: failed to validate initialization: %v", tt.Name, err)
			continue
		}

		err = wh.Validate(context.TODO(), webhooktesting.NewAttribute(ns, nil, false), objectInterfaces)
		if tt.ExpectAllow != (err == nil) {
			t.Errorf("%s: expected allowed=%v, but got err=%v", tt.Name, tt.ExpectAllow, err)
		}

		if tt.ExpectCacheMiss && *cacheMisses == 0 {
			t.Errorf("%s: expected cache miss, but got no AuthenticationInfoResolver call", tt.Name)
		}

		if !tt.ExpectCacheMiss && *cacheMisses > 0 {
			t.Errorf("%s: expected client to be cached, but got %d AuthenticationInfoResolver calls", tt.Name, *cacheMisses)
		}
	}
}

// TestValidateWebhookDuration tests that ValidatingWebhook#Validate sets webhook duration in context correctly
func TestValidateWebhookDuration(ts *testing.T) {
	clk := clocktesting.FakeClock{}
	testServer := webhooktesting.NewTestServerWithHandler(ts, webhooktesting.ClockSteppingWebhookHandler(ts, &clk))
	testServer.StartTLS()
	defer testServer.Close()
	serverURL, err := url.ParseRequestURI(testServer.URL)
	if err != nil {
		ts.Fatalf("this should never happen? %v", err)
	}

	objectInterfaces := webhooktesting.NewObjectInterfacesForTest()

	stopCh := make(chan struct{})
	defer close(stopCh)

	for _, test := range webhooktesting.NewValidationDurationTestCases(serverURL) {
		ts.Run(test.Name, func(t *testing.T) {
			ctx := context.TODO()
			if test.InitContext {
				ctx = request.WithLatencyTrackersAndCustomClock(ctx, &clk)
			}
			wh, err := NewValidatingAdmissionWebhook(nil)
			if err != nil {
				t.Errorf("failed to create mutating webhook: %v", err)
				return
			}

			ns := "webhook-test"
			client, informer := webhooktesting.NewFakeValidatingDataSource(ns, test.Webhooks, stopCh)

			wh.SetAuthenticationInfoResolverWrapper(webhooktesting.Wrapper(webhooktesting.NewAuthenticationInfoResolver(new(int32))))
			wh.SetServiceResolver(webhooktesting.NewServiceResolver(*serverURL))
			wh.SetExternalKubeClientSet(client)
			wh.SetExternalKubeInformerFactory(informer)

			informer.Start(stopCh)
			informer.WaitForCacheSync(stopCh)

			if err = wh.ValidateInitialization(); err != nil {
				t.Errorf("failed to validate initialization: %v", err)
				return
			}

			_ = wh.Validate(ctx, webhooktesting.NewAttribute(ns, nil, test.IsDryRun), objectInterfaces)
			wd, ok := request.LatencyTrackersFrom(ctx)
			if !ok {
				if test.InitContext {
					t.Errorf("expected webhook duration to be initialized")
				}
				return
			}
			if !test.InitContext {
				t.Errorf("expected webhook duration to not be initialized")
				return
			}
			if wd.MutatingWebhookTracker.GetLatency() != 0 {
				t.Errorf("expected admit duration to be equal to 0 got %q", wd.MutatingWebhookTracker.GetLatency())
			}
			if wd.ValidatingWebhookTracker.GetLatency() < test.ExpectedDurationMax {
				t.Errorf("expected validate duraion to be greater or equal to %q got %q", test.ExpectedDurationMax, wd.ValidatingWebhookTracker.GetLatency())
			}
		})
	}
}

// TestValidatePanicHandling tests that panics should not escape the dispatcher
func TestValidatePanicHandling(t *testing.T) {
	testServer := webhooktesting.NewTestServer(t)
	testServer.StartTLS()
	defer testServer.Close()

	objectInterfaces := webhooktesting.NewObjectInterfacesForTest()

	serverURL, err := url.ParseRequestURI(testServer.URL)
	if err != nil {
		t.Fatalf("this should never happen? %v", err)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	for _, tt := range webhooktesting.NewNonMutatingPanicTestCases(serverURL) {
		wh, err := NewValidatingAdmissionWebhook(nil)
		if err != nil {
			t.Errorf("%s: failed to create validating webhook: %v", tt.Name, err)
			continue
		}

		ns := "webhook-test"
		client, informer := webhooktesting.NewFakeValidatingDataSource(ns, tt.Webhooks, stopCh)

		wh.SetAuthenticationInfoResolverWrapper(webhooktesting.Wrapper(webhooktesting.NewPanickingAuthenticationInfoResolver("Start panicking!"))) // see Aladdin, it's awesome
		wh.SetServiceResolver(webhooktesting.NewServiceResolver(*serverURL))
		wh.SetExternalKubeClientSet(client)
		wh.SetExternalKubeInformerFactory(informer)

		informer.Start(stopCh)
		informer.WaitForCacheSync(stopCh)

		if err = wh.ValidateInitialization(); err != nil {
			t.Errorf("%s: failed to validate initialization: %v", tt.Name, err)
			continue
		}

		attr := webhooktesting.NewAttribute(ns, nil, tt.IsDryRun)
		err = wh.Validate(context.TODO(), attr, objectInterfaces)
		if tt.ExpectAllow != (err == nil) {
			t.Errorf("%s: expected allowed=%v, but got err=%v", tt.Name, tt.ExpectAllow, err)
		}
		// ErrWebhookRejected is not an error for our purposes
		if tt.ErrorContains != "" {
			if err == nil || !strings.Contains(err.Error(), tt.ErrorContains) {
				t.Errorf("%s: expected an error saying %q, but got %v", tt.Name, tt.ErrorContains, err)
			}
		}
		if _, isStatusErr := err.(*errors.StatusError); err != nil && !isStatusErr {
			t.Errorf("%s: expected a StatusError, got %T", tt.Name, err)
		}
		fakeAttr, ok := attr.(*webhooktesting.FakeAttributes)
		if !ok {
			t.Errorf("Unexpected error, failed to convert attr to webhooktesting.FakeAttributes")
			continue
		}
		if len(tt.ExpectAnnotations) == 0 {
			assert.Empty(t, fakeAttr.GetAnnotations(auditinternal.LevelMetadata), tt.Name+": annotations not set as expected.")
		} else {
			assert.Equal(t, tt.ExpectAnnotations, fakeAttr.GetAnnotations(auditinternal.LevelMetadata), tt.Name+": annotations not set as expected.")
		}
	}
}

func TestValidatingWebhookExcludedAdmissionResourcesInitializer(t *testing.T) {
	testCases := []struct {
		name              string
		initializeExclude bool
		expectCalls       int32
	}{
		{
			name:              "without initializer dispatches",
			initializeExclude: false,
			expectCalls:       1,
		},
		{
			name:              "initializer wires excluded resources",
			initializeExclude: true,
			expectCalls:       0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ExcludeAdmissionWebhookVirtualResources, true)
			wh, dispatcher := newValidatingExcludedResourceWebhook(t)
			if tc.initializeExclude {
				controlplaneadmission.NewPluginInitializer(nil, []schema.GroupResource{{Group: "authentication.k8s.io", Resource: "tokenreviews"}}).Initialize(wh)
			}

			err := wh.Validate(context.Background(), newTokenReviewAttributes(), newExcludedResourceObjectInterfaces())
			if err != nil {
				t.Fatalf("Validate() returned error: %v", err)
			}
			if got := dispatcher.calls; got != tc.expectCalls {
				t.Fatalf("unexpected webhook dispatch count: got %d, want %d", got, tc.expectCalls)
			}
		})
	}
}

func TestValidatingWebhookExcludedAdmissionResourcesSkipsDispatchWhenGateEnabled(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ExcludeAdmissionWebhookVirtualResources, true)
	wh, dispatcher := newValidatingExcludedResourceWebhook(t)

	wants, ok := any(wh).(admissioninitializer.WantsExcludedAdmissionResources)
	if !ok {
		t.Fatal("validating webhook should implement WantsExcludedAdmissionResources")
	}
	wants.SetExcludedAdmissionResources([]schema.GroupResource{{Group: "authentication.k8s.io", Resource: "tokenreviews"}})

	err := wh.Validate(context.Background(), newTokenReviewAttributes(), newExcludedResourceObjectInterfaces())
	if err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}
	if got := dispatcher.calls; got != 0 {
		t.Fatalf("expected excluded resource to skip dispatch, got %d webhook calls", got)
	}
}

func TestValidatingWebhookExcludedAdmissionResourcesDispatchesWhenGateDisabled(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ExcludeAdmissionWebhookVirtualResources, false)
	wh, dispatcher := newValidatingExcludedResourceWebhook(t)

	wants, ok := any(wh).(admissioninitializer.WantsExcludedAdmissionResources)
	if !ok {
		t.Fatal("validating webhook should implement WantsExcludedAdmissionResources")
	}
	wants.SetExcludedAdmissionResources([]schema.GroupResource{{Group: "authentication.k8s.io", Resource: "tokenreviews"}})

	err := wh.Validate(context.Background(), newTokenReviewAttributes(), newExcludedResourceObjectInterfaces())
	if err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}
	if got := dispatcher.calls; got != 1 {
		t.Fatalf("expected excluded resource to dispatch when gate is disabled, got %d webhook calls", got)
	}
}

func newValidatingExcludedResourceWebhook(t *testing.T) (*Plugin, *countingValidatingDispatcher) {
	t.Helper()

	wh, err := NewValidatingAdmissionWebhook(nil)
	if err != nil {
		t.Fatalf("failed to create validating webhook: %v", err)
	}

	dispatcher := &countingValidatingDispatcher{}
	wh.SetReadyFunc(func() bool { return true })
	setGenericWebhookField(t, wh.Webhook, "dispatcher", dispatcher)
	setGenericWebhookField(t, wh.Webhook, "hookSource", &countingValidatingSource{})

	return wh, dispatcher
}

func newTokenReviewAttributes() admission.Attributes {
	tokenReview := &authenticationv1.TokenReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authenticationv1.SchemeGroupVersion.String(),
			Kind:       "TokenReview",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "tokenreview"},
		Spec: authenticationv1.TokenReviewSpec{
			Token:     "test-token",
			Audiences: []string{"test-audience"},
		},
	}

	return admission.NewAttributesRecord(
		tokenReview,
		nil,
		authenticationv1.SchemeGroupVersion.WithKind("TokenReview"),
		"",
		tokenReview.Name,
		authenticationv1.SchemeGroupVersion.WithResource("tokenreviews"),
		"",
		admission.Create,
		&metav1.CreateOptions{},
		false,
		&user.DefaultInfo{Name: "webhook-test", UID: "webhook-test"},
	)
}

func newExcludedResourceObjectInterfaces() admission.ObjectInterfaces {
	return nil
}

func setGenericWebhookField(t *testing.T, genericWebhook *generic.Webhook, fieldName string, value any) {
	t.Helper()

	field := reflect.ValueOf(genericWebhook).Elem().FieldByName(fieldName)
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
}

type countingValidatingDispatcher struct {
	calls int32
}

func (d *countingValidatingDispatcher) Dispatch(_ context.Context, _ admission.Attributes, _ admission.ObjectInterfaces, _ []webhook.WebhookAccessor) error {
	d.calls++
	return nil
}

type countingValidatingSource struct{}

func (s *countingValidatingSource) Webhooks() []webhook.WebhookAccessor { return nil }
func (s *countingValidatingSource) HasSynced() bool                     { return true }
