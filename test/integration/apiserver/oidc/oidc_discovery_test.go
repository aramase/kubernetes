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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilsoidc "k8s.io/kubernetes/test/utils/oidc"
)

// TestStructuredAuthenticationDiscoveryURL tests that the discovery URL configured in jwt.issuer.discoveryURL is used to
// fetch the discovery document and the issuer in jwt.issuer.url is used to validate the ID token.
func TestStructuredAuthenticationDiscoveryURL(t *testing.T) {
	tests := []struct {
		name         string
		issuerURL    string
		discoveryURL func(baseURL string) string
	}{
		{
			name:         "discovery url and issuer url with no path",
			issuerURL:    "https://example.com",
			discoveryURL: func(baseURL string) string { return baseURL },
		},
		{
			name:         "discovery url has path, issuer url has no path",
			issuerURL:    "https://example.com",
			discoveryURL: func(baseURL string) string { return fmt.Sprintf("%s/c/d/bar", baseURL) },
		},
		{
			name:         "discovery url has no path, issuer url has path",
			issuerURL:    "https://example.com/a/b/foo",
			discoveryURL: func(baseURL string) string { return baseURL },
		},
		{
			name:      "discovery url and issuer url have paths",
			issuerURL: "https://example.com/a/b/foo",
			discoveryURL: func(baseURL string) string {
				return fmt.Sprintf("%s/c/d/bar", baseURL)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			caCertContent, _, caFilePath, caKeyFilePath := generateCert(t)
			signingPrivateKey, publicKey := rsaGenerateKey(t)
			// set the issuer in the discovery document to issuer url (different from the discovery URL) to assert
			// 1. discovery URL is used to fetch the discovery document and
			// 2. issuer in the discovery document is used to validate the ID token
			oidcServer := utilsoidc.BuildAndRunTestServer(t, caFilePath, caKeyFilePath, tt.issuerURL)
			discoveryURL := strings.TrimSuffix(tt.discoveryURL(oidcServer.URL()), "/") + "/.well-known/openid-configuration"

			authenticationConfig := newAuthConfigBuilder(tt.issuerURL, string(caCertContent)).
				withAudiences("foo").
				withAudienceMatchPolicy("MatchAny").
				withDiscoveryURL(discoveryURL).
				withClaimValidationRule(`claims.hd == "example.com"`, "the hd claim must be set to example.com").
				build()

			oidcServer.SetPublicKey(t, publicKey)

			apiServer := startTestAPIServerForOIDC(t, apiServerOIDCConfig{authenticationConfigYAML: authenticationConfig}, publicKey)

			idTokenLifetime := time.Second * 1200
			oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
				t,
				signingPrivateKey,
				map[string]interface{}{
					"iss": tt.issuerURL, // issuer in the discovery document is used to validate the ID token
					"sub": defaultOIDCClaimedUsername,
					"aud": "foo",
					"exp": time.Now().Add(idTokenLifetime).Unix(),
					"hd":  "example.com",
				},
				defaultStubAccessToken,
				defaultStubRefreshToken,
			)).Times(1)

			tokenURL, err := oidcServer.TokenURL()
			require.NoError(t, err)

			client := configureClientFetchingOIDCCredentials(t, apiServer.ClientConfig, caCertContent, caFilePath, oidcServer.URL(), tokenURL)
			ctx := testContext(t)
			res, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
			require.NoError(t, err)
			assert.Equal(t, authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
			}, res.Status.UserInfo)
		})
	}
}
