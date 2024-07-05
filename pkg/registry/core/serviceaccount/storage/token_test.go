/*
Copyright 2024 The Kubernetes Authors.

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

package storage

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	authenticationapi "k8s.io/kubernetes/pkg/apis/authentication"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/features"
)

func TestCreate_TokenREST(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ServiceAccountTokenJTI, true)

	tests := []struct {
		name           string
		input          *authenticationapi.TokenRequest
		ctx            context.Context
		serviceAccount *api.ServiceAccount
		expectedError  string
	}{
		{
			name:           "namespace not in context",
			ctx:            testContext(t),
			serviceAccount: validNewServiceAccount("foo"),
			expectedError:  "namespace is required",
		},
		{
			name:           "request name does not match service account name",
			ctx:            request.WithNamespace(testContext(t), "bar"),
			serviceAccount: validNewServiceAccount("foo"),
			input:          &authenticationapi.TokenRequest{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
			expectedError:  `TokenRequest.authentication.k8s.io "foo" is invalid: metadata.name: Invalid value: "default": must match the service account name if specified`,
		},
		{
			name:           "request namespace does not match service account namespace",
			ctx:            request.WithNamespace(testContext(t), "bar"),
			serviceAccount: validNewServiceAccount("foo"),
			input:          &authenticationapi.TokenRequest{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "default"}},
			expectedError:  `TokenRequest.authentication.k8s.io "foo" is invalid: metadata.namespace: Invalid value: "default": must match the service account namespace if specified`,
		},
		{
			name:           "token request validation fails",
			ctx:            request.WithNamespace(testContext(t), "default"),
			serviceAccount: validNewServiceAccount("foo"),
			input: &authenticationapi.TokenRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "default"},
				Spec:       authenticationapi.TokenRequestSpec{ExpirationSeconds: 0},
			},
			expectedError: `TokenRequest.authentication.k8s.io "" is invalid: spec.expirationSeconds: Invalid value: 0: may not specify a duration less than 10 minutes`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage, server := newStorage(t)
			defer server.Terminate(t)
			defer storage.Store.DestroyFunc()

			if _, err := storage.Store.Create(request.WithNamespace(testContext(t), tt.serviceAccount.Namespace), tt.serviceAccount, rest.ValidateAllObjectFunc, &metav1.CreateOptions{}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			_, err := storage.Token.Create(tt.ctx, tt.serviceAccount.Name, tt.input, rest.ValidateAllObjectFunc, &metav1.CreateOptions{})
			if err == nil || err.Error() != tt.expectedError {
				t.Errorf("expected error %q, got %v", tt.expectedError, err)
			}
		})
	}
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}
