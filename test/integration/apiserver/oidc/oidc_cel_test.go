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
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	kubeapiserverapptesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	utilsoidc "k8s.io/kubernetes/test/utils/oidc"
)

func TestStructuredAuthenticationConfigCEL(t *testing.T) {
	type testRun[K utilsoidc.JosePrivateKey, L utilsoidc.JosePublicKey] struct {
		name                    string
		authConfigFn            authenticationConfigFunc
		configureInfrastructure func(t *testing.T, fn authenticationConfigFunc, keyFunc func(t *testing.T) (K, L)) (
			oidcServer *utilsoidc.TestServer,
			apiServer *kubeapiserverapptesting.TestServer,
			signingPrivateKey *rsa.PrivateKey,
			caCertContent []byte,
			caFilePath string,
		)
		configureOIDCServerBehaviour func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey K)
		configureClient              func(
			t *testing.T,
			restCfg *rest.Config,
			caCert []byte,
			certPath,
			oidcServerURL,
			oidcServerTokenURL string,
		) kubernetes.Interface
		assertErrFn func(t *testing.T, errorToCheck error)
		wantUser    *authenticationv1.UserInfo
	}

	tests := []testRun[*rsa.PrivateKey, *rsa.PublicKey]{
		{
			name: "username CEL expression is ok",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					build()
			},
			configureInfrastructure: configureTestInfrastructure[*rsa.PrivateKey, *rsa.PublicKey],
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				idTokenLifetime := time.Second * 1200
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": defaultOIDCClaimedUsername,
						"aud": defaultOIDCClientID,
						"exp": time.Now().Add(idTokenLifetime).Unix(),
						"jti": "0123456789",
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
			},
			configureClient: configureClientFetchingOIDCCredentials,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			wantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
				Extra: map[string]authenticationv1.ExtraValue{
					// validates credential id is set correctly when jti claim is present
					"authentication.kubernetes.io/credential-id": {"JTI=0123456789"},
				},
			},
		},
		{
			name: "groups CEL expression is ok",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					withGroupsExpression(`(claims.roles.split(",") + claims.other_roles.split(",")).map(role, "prefix:" + role)`).
					build()
			},
			configureInfrastructure: configureTestInfrastructure[*rsa.PrivateKey, *rsa.PublicKey],
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				idTokenLifetime := time.Second * 1200
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss":         oidcServer.URL(),
						"sub":         defaultOIDCClaimedUsername,
						"aud":         defaultOIDCClientID,
						"exp":         time.Now().Add(idTokenLifetime).Unix(),
						"roles":       "foo,bar",
						"other_roles": "baz,qux",
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
			},
			configureClient: configureClientFetchingOIDCCredentials,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			wantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"prefix:foo", "prefix:bar", "prefix:baz", "prefix:qux", "system:authenticated"},
			},
		},
		{
			name: "claim validation rule fails",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					withClaimValidationRule(`claims.hd == "example.com"`, "the hd claim must be set to example.com").
					build()
			},
			configureInfrastructure: configureTestInfrastructure[*rsa.PrivateKey, *rsa.PublicKey],
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				idTokenLifetime := time.Second * 1200
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": defaultOIDCClaimedUsername,
						"aud": defaultOIDCClientID,
						"exp": time.Now().Add(idTokenLifetime).Unix(),
						"hd":  "notexample.com",
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
			},
			configureClient: configureClientFetchingOIDCCredentials,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.True(t, apierrors.IsUnauthorized(errorToCheck), errorToCheck)
			},
		},
		{
			name: "extra mapping CEL expressions are ok",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					withExtra("example.org/foo", "'bar'").
					withExtra("example.org/baz", "claims.baz").
					withUserValidationRule(`'bar' in user.extra['example.org/foo'] && 'qux' in user.extra['example.org/baz']`, "example.org/foo must be bar and example.org/baz must be qux").
					build()
			},
			configureInfrastructure: configureTestInfrastructure[*rsa.PrivateKey, *rsa.PublicKey],
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				idTokenLifetime := time.Second * 1200
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": defaultOIDCClaimedUsername,
						"aud": defaultOIDCClientID,
						"exp": time.Now().Add(idTokenLifetime).Unix(),
						"baz": "qux",
						"jti": "0123456789",
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
			},
			configureClient: configureClientFetchingOIDCCredentials,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			wantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
				Extra: map[string]authenticationv1.ExtraValue{
					// validates credential id is set correctly and other extra fields are set
					"authentication.kubernetes.io/credential-id": {"JTI=0123456789"},
					"example.org/foo": {"bar"},
					"example.org/baz": {"qux"},
				},
			},
		},
		{
			name: "uid CEL expression is ok",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					withUIDExpression("claims.uid").
					build()
			},
			configureInfrastructure: configureTestInfrastructure[*rsa.PrivateKey, *rsa.PublicKey],
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				idTokenLifetime := time.Second * 1200
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": defaultOIDCClaimedUsername,
						"aud": defaultOIDCClientID,
						"exp": time.Now().Add(idTokenLifetime).Unix(),
						"uid": "1234",
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
			},
			configureClient: configureClientFetchingOIDCCredentials,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			wantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
				UID:      "1234",
			},
		},
		{
			name: "user validation rule fails",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					withGroupsExpression(`(claims.roles.split(",") + claims.other_roles.split(",")).map(role, "system:" + role)`).
					withUserValidationRule(`user.groups.all(group, !group.startsWith('system:'))`, "groups cannot used reserved system: prefix").
					build()
			},
			configureInfrastructure: configureTestInfrastructure[*rsa.PrivateKey, *rsa.PublicKey],
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				idTokenLifetime := time.Second * 1200
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss":         oidcServer.URL(),
						"sub":         defaultOIDCClaimedUsername,
						"aud":         defaultOIDCClientID,
						"exp":         time.Now().Add(idTokenLifetime).Unix(),
						"roles":       "foo,bar",
						"other_roles": "baz,qux",
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
			},
			configureClient: configureClientFetchingOIDCCredentials,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.True(t, apierrors.IsUnauthorized(errorToCheck), errorToCheck)
			},
			wantUser: nil,
		},
		{
			name: "multiple audiences check with claim validation rule is ok",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences("baz", "foo").
					withAudienceMatchPolicy("MatchAny").
					withUIDExpression("claims.uid").
					withClaimValidationRule(`sets.equivalent(claims.aud, ["bar", "foo", "baz"])`, `aud claim must be exactly match list ["bar", "foo", "baz"]`).
					build()
			},
			configureInfrastructure: configureTestInfrastructure[*rsa.PrivateKey, *rsa.PublicKey],
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				idTokenLifetime := time.Second * 1200
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": defaultOIDCClaimedUsername,
						"aud": []string{"foo", "bar", "baz"},
						"exp": time.Now().Add(idTokenLifetime).Unix(),
						"uid": "1234",
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
			},
			configureClient: configureClientFetchingOIDCCredentials,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			wantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
				UID:      "1234",
			},
		},
		{
			name: "non-string jti claim doesn't result in authentication error",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					build()
			},
			configureInfrastructure: configureTestInfrastructure[*rsa.PrivateKey, *rsa.PublicKey],
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				idTokenLifetime := time.Second * 1200
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": defaultOIDCClaimedUsername,
						"aud": defaultOIDCClientID,
						"exp": time.Now().Add(idTokenLifetime).Unix(),
						"jti": 1234,
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
			},
			configureClient: configureClientFetchingOIDCCredentials,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			wantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
			},
		},
		{
			name: "egress proxy is ok",
			authConfigFn: func(t *testing.T, issuerURL, caCert string) string {
				return newAuthConfigBuilder(issuerURL, caCert).
					withAudiences(defaultOIDCClientID, "another-audience").
					withAudienceMatchPolicy("MatchAny").
					withEgressSelectorType("cluster").
					build()
			},
			configureInfrastructure: configureTestInfrastructureWithEgressProxy[*rsa.PrivateKey, *rsa.PublicKey],
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				idTokenLifetime := time.Second * 1200
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": defaultOIDCClaimedUsername,
						"aud": defaultOIDCClientID,
						"exp": time.Now().Add(idTokenLifetime).Unix(),
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
			},
			configureClient: configureClientFetchingOIDCCredentials,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
			wantUser: &authenticationv1.UserInfo{
				Username: "k8s-john_doe",
				Groups:   []string{"system:authenticated"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			oidcServer, apiServer, signingPrivateKey, caCert, certPath := tt.configureInfrastructure(t, tt.authConfigFn, rsaGenerateKey)

			tt.configureOIDCServerBehaviour(t, oidcServer, signingPrivateKey)

			tokenURL, err := oidcServer.TokenURL()
			require.NoError(t, err)

			client := tt.configureClient(t, apiServer.ClientConfig, caCert, certPath, oidcServer.URL(), tokenURL)

			ctx := testContext(t)

			if tt.wantUser != nil {
				res, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
				require.NoError(t, err)
				assert.Equal(t, *tt.wantUser, res.Status.UserInfo)
			}

			_, err = client.CoreV1().Pods(defaultNamespace).List(ctx, metav1.ListOptions{})
			tt.assertErrFn(t, err)
		})
	}
}
