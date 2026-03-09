/*
Copyright 2023 The Kubernetes Authors.

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

package oidc

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	genericapiserver "k8s.io/apiserver/pkg/server"
	authenticationconfigmetrics "k8s.io/apiserver/pkg/server/options/authenticationconfig/metrics"
	"k8s.io/client-go/kubernetes"
	kubeapiserverapptesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/pkg/kubeapiserver/options"
	utilsoidc "k8s.io/kubernetes/test/utils/oidc"
)

func TestStructuredAuthenticationConfigReload(t *testing.T) {
	genericapiserver.SetHostnameFuncForTests("testAPIServerID")
	const hardCodedTokenCacheTTLAndPollInterval = 10 * time.Second

	origUpdateAuthenticationConfigTimeout := options.UpdateAuthenticationConfigTimeout
	t.Cleanup(func() { options.UpdateAuthenticationConfigTimeout = origUpdateAuthenticationConfigTimeout })
	options.UpdateAuthenticationConfigTimeout = 2 * hardCodedTokenCacheTTLAndPollInterval // needs to be large enough for polling to run multiple times

	tests := []struct {
		name                          string
		authConfigFn, newAuthConfigFn authenticationConfigFunc
		configureTestInfrastructure   func(t *testing.T, fn authenticationConfigFunc) (*utilsoidc.TestServer, *kubeapiserverapptesting.TestServer, []byte, string)
		assertErrFn, newAssertErrFn   func(t *testing.T, errorToCheck error)
		wantUser, newWantUser         *authenticationv1.UserInfo
		ignoreTransitionErrFn         func(error) bool
		waitAfterConfigSwap           bool
		wantMetricStrings             []string
	}{
		{
			name: "old valid config to new valid config",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					build()
			},
			newAuthConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					withUsernameExpression("'panda-' + claims.sub").
					build()
			},
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			wantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
			},
			newAssertErrFn: func(t *testing.T, errorToCheck error) {
				_ = assert.True(t, apierrors.IsForbidden(errorToCheck)) &&
					assert.Equal(
						t,
						`pods is forbidden: User "panda-john_doe" cannot list resource "pods" in API group "" in the namespace "default"`,
						errorToCheck.Error(),
					)
			},
			newWantUser: &authenticationv1.UserInfo{
				Username: "panda-john_doe",
				Groups:   []string{"system:authenticated"},
			},
			wantMetricStrings: []string{
				`apiserver_authentication_config_controller_automatic_reload_last_timestamp_seconds{apiserver_id_hash="` + testAPIServerIDHash + `",status="success"} FP`,
				`apiserver_authentication_config_controller_automatic_reloads_total{apiserver_id_hash="` + testAPIServerIDHash + `",status="success"} 1`,
				`apiserver_authentication_config_controller_last_config_info{apiserver_id_hash="` + testAPIServerIDHash + `",hash="replace_with_new_config_hash"} 1`,
			},
		},
		{
			name: "old to new config with egress", // both configs are valid, but need to keep the test name short otherwise the UDS name can get too long on macOS
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					build()
			},
			newAuthConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					withEgressSelectorType("cluster").
					withUsernameExpression("'panda-' + claims.sub").
					build()
			},
			configureTestInfrastructure: func(t *testing.T, fn authenticationConfigFunc) (*utilsoidc.TestServer, *kubeapiserverapptesting.TestServer, []byte, string) {
				t.Helper()

				oidcServer, apiServer, signingPrivateKey, caCertContent, caFilePath := configureTestInfrastructureWithEgressProxy(t, fn, ecdsaGenerateKey)

				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": defaultOIDCClaimedUsername,
						"aud": defaultOIDCClientID,
						"exp": time.Now().Add(10 * time.Minute).Unix(),
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)

				return oidcServer, apiServer, caCertContent, caFilePath
			},
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			wantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
			},
			newAssertErrFn: func(t *testing.T, errorToCheck error) {
				_ = assert.True(t, apierrors.IsForbidden(errorToCheck)) &&
					assert.Equal(
						t,
						`pods is forbidden: User "panda-john_doe" cannot list resource "pods" in API group "" in the namespace "default"`,
						errorToCheck.Error(),
					)
			},
			newWantUser: &authenticationv1.UserInfo{
				Username: "panda-john_doe",
				Groups:   []string{"system:authenticated"},
			},
			wantMetricStrings: []string{
				`apiserver_authentication_config_controller_automatic_reload_last_timestamp_seconds{apiserver_id_hash="` + testAPIServerIDHash + `",status="success"} FP`,
				`apiserver_authentication_config_controller_automatic_reloads_total{apiserver_id_hash="` + testAPIServerIDHash + `",status="success"} 1`,
				`apiserver_authentication_config_controller_last_config_info{apiserver_id_hash="` + testAPIServerIDHash + `",hash="replace_with_new_config_hash"} 1`,
			},
		},
		{
			name: "old empty config to new valid config",
			authConfigFn: func(t *testing.T, _, _ string) string {
				return newEmptyAuthConfig().build()
			},
			newAuthConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					withUsernameExpression("'snorlax-' + claims.sub").
					build()
			},
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.True(t, apierrors.IsUnauthorized(errorToCheck))
			},
			wantUser:              nil,
			ignoreTransitionErrFn: apierrors.IsUnauthorized,
			newAssertErrFn: func(t *testing.T, errorToCheck error) {
				_ = assert.True(t, apierrors.IsForbidden(errorToCheck)) &&
					assert.Equal(
						t,
						`pods is forbidden: User "snorlax-john_doe" cannot list resource "pods" in API group "" in the namespace "default"`,
						errorToCheck.Error(),
					)
			},
			newWantUser: &authenticationv1.UserInfo{
				Username: "snorlax-john_doe",
				Groups:   []string{"system:authenticated"},
			},
			wantMetricStrings: []string{
				`apiserver_authentication_config_controller_automatic_reload_last_timestamp_seconds{apiserver_id_hash="` + testAPIServerIDHash + `",status="success"} FP`,
				`apiserver_authentication_config_controller_automatic_reloads_total{apiserver_id_hash="` + testAPIServerIDHash + `",status="success"} 1`,
				`apiserver_authentication_config_controller_last_config_info{apiserver_id_hash="` + testAPIServerIDHash + `",hash="replace_with_new_config_hash"} 1`,
			},
		},
		{
			name: "old invalid config to new valid config",
			authConfigFn: func(t *testing.T, issuerURL, _ string) string {
				return newAuthConfigBuilder(issuerURL, "").
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					withEmptyCertificateAuthority().
					build()
			},
			newAuthConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					build()
			},
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.True(t, apierrors.IsUnauthorized(errorToCheck))
			},
			wantUser:              nil,
			ignoreTransitionErrFn: apierrors.IsUnauthorized,
			newAssertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			newWantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
			},
			wantMetricStrings: []string{
				`apiserver_authentication_config_controller_automatic_reload_last_timestamp_seconds{apiserver_id_hash="` + testAPIServerIDHash + `",status="success"} FP`,
				`apiserver_authentication_config_controller_automatic_reloads_total{apiserver_id_hash="` + testAPIServerIDHash + `",status="success"} 1`,
				`apiserver_authentication_config_controller_last_config_info{apiserver_id_hash="` + testAPIServerIDHash + `",hash="replace_with_new_config_hash"} 1`,
			},
		},
		{
			name: "old valid config to new structurally invalid config (should be ignored)",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					build()
			},
			newAuthConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					withUsernameExpression("'k8s-' + claimss.sub").
					build()
			},
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			wantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
			},
			newAssertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			newWantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
			},
			waitAfterConfigSwap: true,
			wantMetricStrings: []string{
				`apiserver_authentication_config_controller_automatic_reload_last_timestamp_seconds{apiserver_id_hash="` + testAPIServerIDHash + `",status="failure"} FP`,
				`apiserver_authentication_config_controller_automatic_reloads_total{apiserver_id_hash="` + testAPIServerIDHash + `",status="failure"} 1`,
				`apiserver_authentication_config_controller_last_config_info{apiserver_id_hash="` + testAPIServerIDHash + `",hash="replace_with_old_config_hash"} 1`,
			},
		},
		{
			name: "old valid config to new valid empty config (should cause tokens to stop working)",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					build()
			},
			newAuthConfigFn: func(t *testing.T, _, _ string) string {
				return newEmptyAuthConfig().build()
			},
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			wantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
			},
			newAssertErrFn: func(t *testing.T, errorToCheck error) {
				assert.True(t, apierrors.IsUnauthorized(errorToCheck))
			},
			newWantUser:         nil,
			waitAfterConfigSwap: true,
			wantMetricStrings: []string{
				`apiserver_authentication_config_controller_automatic_reload_last_timestamp_seconds{apiserver_id_hash="` + testAPIServerIDHash + `",status="success"} FP`,
				`apiserver_authentication_config_controller_automatic_reloads_total{apiserver_id_hash="` + testAPIServerIDHash + `",status="success"} 1`,
				`apiserver_authentication_config_controller_last_config_info{apiserver_id_hash="` + testAPIServerIDHash + `",hash="replace_with_new_config_hash"} 1`,
			},
		},
		{
			name: "old valid config to new valid config with typo (should be ignored)",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					build()
			},
			newAuthConfigFn: func(t *testing.T, issuerURL, _ string) string {
				return newAuthConfigBuilder(issuerURL, "").
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					withEmptyCertificateAuthority().
					build()
			},
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			wantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
			},
			newAssertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			newWantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
			},
			waitAfterConfigSwap: true,
			wantMetricStrings: []string{
				`apiserver_authentication_config_controller_automatic_reload_last_timestamp_seconds{apiserver_id_hash="` + testAPIServerIDHash + `",status="failure"} FP`,
				`apiserver_authentication_config_controller_automatic_reloads_total{apiserver_id_hash="` + testAPIServerIDHash + `",status="failure"} 1`,
				`apiserver_authentication_config_controller_last_config_info{apiserver_id_hash="` + testAPIServerIDHash + `",hash="replace_with_old_config_hash"} 1`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authenticationconfigmetrics.ResetMetricsForTest()
			defer authenticationconfigmetrics.ResetMetricsForTest()

			ctx := testContext(t)

			configureTestInfrastructureFunc := tt.configureTestInfrastructure
			if configureTestInfrastructureFunc == nil {
				configureTestInfrastructureFunc = configureBasicTestInfrastructureWithRSAKey
			}
			oidcServer, apiServer, caCert, certPath := configureTestInfrastructureFunc(t, tt.authConfigFn)

			tokenURL, err := oidcServer.TokenURL()
			require.NoError(t, err)

			client := configureClientFetchingOIDCCredentials(t, apiServer.ClientConfig, caCert, certPath, oidcServer.URL(), tokenURL)

			if tt.wantUser != nil {
				res, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
				require.NoError(t, err)
				assert.Equal(t, *tt.wantUser, res.Status.UserInfo)
			}

			_, err = client.CoreV1().Pods(defaultNamespace).List(ctx, metav1.ListOptions{})
			tt.assertErrFn(t, err)

			// Create a temporary file
			tempFile, err := os.CreateTemp("", "tempfile")
			require.NoError(t, err)
			defer func() {
				_ = tempFile.Close()
			}()

			newAuthConfig := tt.newAuthConfigFn(t, oidcServer.URL(), string(caCert))
			// Write the new content to the temporary file
			_, err = tempFile.Write([]byte(newAuthConfig))
			require.NoError(t, err)

			// Atomically replace the original file with the temporary file
			err = os.Rename(tempFile.Name(), apiServer.ServerOpts.Authentication.AuthenticationConfigFile)
			require.NoError(t, err)

			if tt.waitAfterConfigSwap {
				// Poll until the reload controller has processed the config change,
				// rather than sleeping unconditionally.
				adminClient := kubernetes.NewForConfigOrDie(apiServer.ClientConfig)
				err = wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, options.UpdateAuthenticationConfigTimeout+hardCodedTokenCacheTTLAndPollInterval, true, func(ctx context.Context) (done bool, err error) {
					gotMetricStrings := getMetrics(t, ctx, adminClient, "apiserver_authentication_config_controller_automatic_reloads_total")
					return len(gotMetricStrings) > 0, nil
				})
				if err != nil {
					t.Logf("timed out waiting for config reload attempt: %v", err)
				}
				// Wait for the token cache to expire after the reload is detected.
				time.Sleep(hardCodedTokenCacheTTLAndPollInterval + time.Second)
			}

			if tt.newWantUser != nil {
				start := time.Now()
				err = wait.PollUntilContextTimeout(ctx, time.Second, 3*hardCodedTokenCacheTTLAndPollInterval, true, func(ctx context.Context) (done bool, err error) {
					res, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
					if err != nil {
						if tt.ignoreTransitionErrFn != nil && tt.ignoreTransitionErrFn(err) {
							return false, nil
						}
						return false, err
					}

					diff := cmp.Diff(*tt.newWantUser, res.Status.UserInfo)
					if len(diff) > 0 && time.Since(start) > 2*hardCodedTokenCacheTTLAndPollInterval {
						t.Logf("%s saw new user diff:\n%s", t.Name(), diff)
					}

					return len(diff) == 0, nil
				})
				require.NoError(t, err, "new authentication config not loaded")
			}

			_, err = client.CoreV1().Pods(defaultNamespace).List(ctx, metav1.ListOptions{})
			tt.newAssertErrFn(t, err)

			oldAuthConfigHash := getHash(tt.authConfigFn(t, oidcServer.URL(), string(caCert)))
			newAuthConfigHash := getHash(newAuthConfig)
			for i := range tt.wantMetricStrings {
				if strings.Contains(tt.wantMetricStrings[i], "replace_with_new_config_hash") {
					tt.wantMetricStrings[i] = strings.ReplaceAll(tt.wantMetricStrings[i], "replace_with_new_config_hash", newAuthConfigHash)
				} else if strings.Contains(tt.wantMetricStrings[i], "replace_with_old_config_hash") {
					tt.wantMetricStrings[i] = strings.ReplaceAll(tt.wantMetricStrings[i], "replace_with_old_config_hash", oldAuthConfigHash)
				}
			}

			adminClient := kubernetes.NewForConfigOrDie(apiServer.ClientConfig)
			gotMetricStrings := getMetrics(t, ctx, adminClient, "apiserver_authentication_config_controller_")
			if diff := cmp.Diff(tt.wantMetricStrings, gotMetricStrings); diff != "" {
				t.Errorf("unexpected metrics diff (-want +got): %s", diff)
			}
		})
	}
}
