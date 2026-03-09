/*
Copyright 2025 The Kubernetes Authors.

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
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/features"
	genericapiserver "k8s.io/apiserver/pkg/server"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/client-go/kubernetes"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/kubernetes/pkg/kubeapiserver/options"
	utilsoidc "k8s.io/kubernetes/test/utils/oidc"
)

func TestMultipleJWTAuthenticators(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.StructuredAuthenticationConfigurationJWKSMetrics, true)

	genericapiserver.SetHostnameFuncForTests("testAPIServerID")
	oidc.ResetMetrics()

	caCertContent1, _, caFilePath1, caKeyFilePath1 := generateCert(t)
	signingPrivateKey1, publicKey1 := rsaGenerateKey(t)
	oidcServer1 := utilsoidc.BuildAndRunTestServer(t, caFilePath1, caKeyFilePath1, "")

	caCertContent2, _, caFilePath2, caKeyFilePath2 := generateCert(t)
	signingPrivateKey2, publicKey2 := rsaGenerateKey(t)
	oidcServer2 := utilsoidc.BuildAndRunTestServer(t, caFilePath2, caKeyFilePath2, "https://example.com")

	authenticationConfig := newMultiIssuerAuthConfig().
		addIssuer(oidcServer1.URL(), string(caCertContent1)).
		withAudiences("foo").
		withAudienceMatchPolicy("MatchAny").
		withClaimValidationRule(`claims.hd == "example.com"`, "the hd claim must be set to example.com").
		addIssuer("https://example.com", string(caCertContent2)).
		withDiscoveryURL(oidcServer2.URL() + "/.well-known/openid-configuration").
		withAudiences("bar").
		withAudienceMatchPolicy("MatchAny").
		withGroupsExpression(`(claims.roles.split(",") + claims.other_roles.split(",")).map(role, "system:" + role)`).
		withUIDExpression("claims.uid").
		build()

	oidcServer1.SetPublicKey(t, publicKey1)
	oidcServer2.SetPublicKey(t, publicKey2)

	apiServer := startTestAPIServerForOIDC(t, apiServerOIDCConfig{authenticationConfigYAML: authenticationConfig}, publicKey1)

	idTokenLifetime := time.Second * 1200
	oidcServer1.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
		t,
		signingPrivateKey1,
		map[string]interface{}{
			"iss": oidcServer1.URL(),
			"sub": defaultOIDCClaimedUsername,
			"aud": "foo",
			"exp": time.Now().Add(idTokenLifetime).Unix(),
			"hd":  "example.com",
		},
		defaultStubAccessToken,
		defaultStubRefreshToken,
	)).Times(1)

	oidcServer2.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
		t,
		signingPrivateKey2,
		map[string]interface{}{
			"iss":         "https://example.com",
			"sub":         "not_john_doe",
			"aud":         "bar",
			"roles":       "role1,role2",
			"other_roles": "role3,role4",
			"exp":         time.Now().Add(idTokenLifetime).Unix(),
			"uid":         "1234",
		},
		defaultStubAccessToken,
		defaultStubRefreshToken,
	)).Times(1)

	tokenURL1, err := oidcServer1.TokenURL()
	require.NoError(t, err)

	tokenURL2, err := oidcServer2.TokenURL()
	require.NoError(t, err)

	client1 := configureClientFetchingOIDCCredentials(t, apiServer.ClientConfig, caCertContent1, caFilePath1, oidcServer1.URL(), tokenURL1)
	client2 := configureClientFetchingOIDCCredentials(t, apiServer.ClientConfig, caCertContent2, caFilePath2, oidcServer2.URL(), tokenURL2)

	ctx := testContext(t)
	res, err := client1.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	require.NoError(t, err)
	assert.Equal(t, authenticationv1.UserInfo{
		Username: "k8s-john_doe",
		Groups:   []string{"system:authenticated"},
	}, res.Status.UserInfo)

	res, err = client2.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	require.NoError(t, err)
	assert.Equal(t, authenticationv1.UserInfo{
		Username: "k8s-not_john_doe",
		Groups:   []string{"system:role1", "system:role2", "system:role3", "system:role4", "system:authenticated"},
		UID:      "1234",
	}, res.Status.UserInfo)

	jwtIssuerHash1 := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(oidcServer1.URL())))
	jwtIssuerHash2 := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("https://example.com")))

	keySetHash1 := fetchJWKSAndComputeHash(t, oidcServer1.URL(), caCertContent1)
	keySetHash2 := fetchJWKSAndComputeHash(t, oidcServer2.URL(), caCertContent2)

	wantMetricStrings := []string{
		fmt.Sprintf(`apiserver_authentication_jwt_authenticator_jwks_fetch_last_key_set_info{apiserver_id_hash="`+testAPIServerIDHash+`",hash="%s",jwt_issuer_hash="%s"} 1`, keySetHash1, jwtIssuerHash1),
		fmt.Sprintf(`apiserver_authentication_jwt_authenticator_jwks_fetch_last_key_set_info{apiserver_id_hash="`+testAPIServerIDHash+`",hash="%s",jwt_issuer_hash="%s"} 1`, keySetHash2, jwtIssuerHash2),
		fmt.Sprintf(`apiserver_authentication_jwt_authenticator_jwks_fetch_last_timestamp_seconds{apiserver_id_hash="`+testAPIServerIDHash+`",jwt_issuer_hash="%s",result="success"} FP`, jwtIssuerHash1),
		fmt.Sprintf(`apiserver_authentication_jwt_authenticator_jwks_fetch_last_timestamp_seconds{apiserver_id_hash="`+testAPIServerIDHash+`",jwt_issuer_hash="%s",result="success"} FP`, jwtIssuerHash2),
	}
	adminClient := kubernetes.NewForConfigOrDie(apiServer.ClientConfig)
	gotMetricStrings := getMetrics(t, ctx, adminClient, "apiserver_authentication_jwt_authenticator_jwks_")

	slices.Sort(wantMetricStrings)

	if diff := cmp.Diff(wantMetricStrings, gotMetricStrings); diff != "" {
		t.Errorf("unexpected metrics diff (-want +got): %s", diff)
	}
}

// TestJWKSMetricsCleanupOnIssuerRemoval tests that metrics are cleaned up when an issuer is removed.
// 1. Start with two issuers configured and verify that metrics for both issuers exist.
// 2. Remove one issuer from the config and verify that metrics for the removed issuer are deleted.
func TestJWKSMetricsCleanupOnIssuerRemoval(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.StructuredAuthenticationConfigurationJWKSMetrics, true)

	genericapiserver.SetHostnameFuncForTests("testAPIServerID")
	oidc.ResetMetrics()

	const hardCodedTokenCacheTTLAndPollInterval = 10 * time.Second
	origUpdateAuthenticationConfigTimeout := options.UpdateAuthenticationConfigTimeout
	t.Cleanup(func() { options.UpdateAuthenticationConfigTimeout = origUpdateAuthenticationConfigTimeout })
	options.UpdateAuthenticationConfigTimeout = 2 * hardCodedTokenCacheTTLAndPollInterval

	caCertContent1, _, caFilePath1, caKeyFilePath1 := generateCert(t)
	signingPrivateKey1, publicKey1 := rsaGenerateKey(t)
	oidcServer1 := utilsoidc.BuildAndRunTestServer(t, caFilePath1, caKeyFilePath1, "")

	caCertContent2, _, caFilePath2, caKeyFilePath2 := generateCert(t)
	signingPrivateKey2, publicKey2 := rsaGenerateKey(t)
	oidcServer2 := utilsoidc.BuildAndRunTestServer(t, caFilePath2, caKeyFilePath2, "")

	authenticationConfig := newMultiIssuerAuthConfig().
		addIssuer(oidcServer1.URL(), string(caCertContent1)).
		withAudiences("foo").
		withAudienceMatchPolicy("MatchAny").
		addIssuer(oidcServer2.URL(), string(caCertContent2)).
		withAudiences("bar").
		withAudienceMatchPolicy("MatchAny").
		build()

	oidcServer1.SetPublicKey(t, publicKey1)
	oidcServer2.SetPublicKey(t, publicKey2)

	apiServer := startTestAPIServerForOIDC(t, apiServerOIDCConfig{
		authenticationConfigYAML: authenticationConfig,
	}, publicKey1)

	idTokenLifetime := time.Second * 1200
	oidcServer1.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
		t,
		signingPrivateKey1,
		map[string]interface{}{
			"iss": oidcServer1.URL(),
			"sub": defaultOIDCClaimedUsername,
			"aud": "foo",
			"exp": time.Now().Add(idTokenLifetime).Unix(),
		},
		defaultStubAccessToken,
		defaultStubRefreshToken,
	)).Times(1)

	oidcServer2.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
		t,
		signingPrivateKey2,
		map[string]interface{}{
			"iss": oidcServer2.URL(),
			"sub": defaultOIDCClaimedUsername,
			"aud": "bar",
			"exp": time.Now().Add(idTokenLifetime).Unix(),
		},
		defaultStubAccessToken,
		defaultStubRefreshToken,
	)).Times(1)

	ctx := testContext(t)

	tokenURL1, err := oidcServer1.TokenURL()
	require.NoError(t, err)
	tokenURL2, err := oidcServer2.TokenURL()
	require.NoError(t, err)

	client1 := configureClientFetchingOIDCCredentials(t, apiServer.ClientConfig, caCertContent1, caFilePath1, oidcServer1.URL(), tokenURL1)
	_, err = client1.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	require.NoError(t, err)

	client2 := configureClientFetchingOIDCCredentials(t, apiServer.ClientConfig, caCertContent2, caFilePath2, oidcServer2.URL(), tokenURL2)
	_, err = client2.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	require.NoError(t, err)

	jwtIssuerHash1 := getHash(oidcServer1.URL())
	jwtIssuerHash2 := getHash(oidcServer2.URL())

	keySetHash1 := fetchJWKSAndComputeHash(t, oidcServer1.URL(), caCertContent1)
	keySetHash2 := fetchJWKSAndComputeHash(t, oidcServer2.URL(), caCertContent2)

	adminClient := kubernetes.NewForConfigOrDie(apiServer.ClientConfig)

	// Check that metrics exist for both the issuers with correct jwt_issuer_hash + hash combos
	wantMetricStrings := []string{
		fmt.Sprintf(`apiserver_authentication_jwt_authenticator_jwks_fetch_last_key_set_info{apiserver_id_hash="`+testAPIServerIDHash+`",hash="%s",jwt_issuer_hash="%s"} 1`, keySetHash1, jwtIssuerHash1),
		fmt.Sprintf(`apiserver_authentication_jwt_authenticator_jwks_fetch_last_key_set_info{apiserver_id_hash="`+testAPIServerIDHash+`",hash="%s",jwt_issuer_hash="%s"} 1`, keySetHash2, jwtIssuerHash2),
		fmt.Sprintf(`apiserver_authentication_jwt_authenticator_jwks_fetch_last_timestamp_seconds{apiserver_id_hash="`+testAPIServerIDHash+`",jwt_issuer_hash="%s",result="success"} FP`, jwtIssuerHash1),
		fmt.Sprintf(`apiserver_authentication_jwt_authenticator_jwks_fetch_last_timestamp_seconds{apiserver_id_hash="`+testAPIServerIDHash+`",jwt_issuer_hash="%s",result="success"} FP`, jwtIssuerHash2),
	}
	gotMetricStrings := getMetrics(t, ctx, adminClient, "apiserver_authentication_jwt_authenticator_jwks_")

	slices.Sort(wantMetricStrings)
	if diff := cmp.Diff(wantMetricStrings, gotMetricStrings); diff != "" {
		t.Errorf("unexpected metrics before reload diff (-want +got): %s", diff)
	}

	// Now update the config to only have ONE issuer (remove issuer 2)
	newAuthenticationConfig := newAuthConfigBuilder(oidcServer1.URL(), string(caCertContent1)).
		withAudiences("foo").
		withAudienceMatchPolicy("MatchAny").
		build()

	authConfigFilePath := apiServer.ServerOpts.Authentication.AuthenticationConfigFile

	tempFile, err := os.CreateTemp(filepath.Dir(authConfigFilePath), "auth-config-*.yaml")
	require.NoError(t, err)
	_, err = tempFile.Write([]byte(newAuthenticationConfig))
	require.NoError(t, err)
	err = tempFile.Close()
	require.NoError(t, err)

	err = os.Rename(tempFile.Name(), authConfigFilePath)
	require.NoError(t, err)

	newAuthConfigHash := getHash(newAuthenticationConfig)

	// Wait for config reload by polling for the new config hash
	err = wait.PollUntilContextTimeout(ctx, time.Second, 3*hardCodedTokenCacheTTLAndPollInterval, true, func(ctx context.Context) (done bool, err error) {
		body, err := adminClient.RESTClient().Get().AbsPath("/metrics").DoRaw(ctx)
		if err != nil {
			return false, err
		}

		metricsStr := string(body)
		expectedConfigHashMetric := fmt.Sprintf(`apiserver_authentication_config_controller_last_config_info{apiserver_id_hash="`+testAPIServerIDHash+`",hash="%s"} 1`, newAuthConfigHash)
		return strings.Contains(metricsStr, expectedConfigHashMetric), nil
	})
	require.NoError(t, err, "config reload not detected")

	// Wait for metric cleanup by polling until issuer 2 metrics are removed
	wantMetricStringsAfterReload := []string{
		fmt.Sprintf(`apiserver_authentication_jwt_authenticator_jwks_fetch_last_key_set_info{apiserver_id_hash="`+testAPIServerIDHash+`",hash="%s",jwt_issuer_hash="%s"} 1`, keySetHash1, jwtIssuerHash1),
		fmt.Sprintf(`apiserver_authentication_jwt_authenticator_jwks_fetch_last_timestamp_seconds{apiserver_id_hash="`+testAPIServerIDHash+`",jwt_issuer_hash="%s",result="success"} FP`, jwtIssuerHash1),
	}
	slices.Sort(wantMetricStringsAfterReload)

	err = wait.PollUntilContextTimeout(ctx, time.Second, 120*time.Second, true, func(ctx context.Context) (done bool, err error) {
		gotMetricStrings := getMetrics(t, ctx, adminClient, "apiserver_authentication_jwt_authenticator_jwks_")
		diff := cmp.Diff(wantMetricStringsAfterReload, gotMetricStrings)
		return len(diff) == 0, nil
	})
	require.NoError(t, err, "metrics cleanup not completed - issuer 2 metrics still present")
}
