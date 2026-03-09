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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
	kubeapiserverapptesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	utilsoidc "k8s.io/kubernetes/test/utils/oidc"
	"k8s.io/kubernetes/test/utils/oidc/handlers"
	utilsnet "k8s.io/utils/net"
)

func TestOIDC(t *testing.T) {
	t.Log("Testing OIDC authenticator with --oidc-* flags")
	genericapiserver.SetHostnameFuncForTests("testAPIServerID")

	// Tests that need their own server (custom infrastructure).
	for _, tt := range []singleTest[*rsa.PrivateKey, *rsa.PublicKey]{
		{
			name: "ID token is ok",
			configureInfrastructure: func(t *testing.T, _ authenticationConfigFunc, keyFunc func(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey)) (
				oidcServer *utilsoidc.TestServer,
				apiServer *kubeapiserverapptesting.TestServer,
				signingPrivateKey *rsa.PrivateKey,
				caCertContent []byte,
				caFilePath string,
			) {
				caCertContent, _, caFilePath, caKeyFilePath := generateCert(t)
				signingPrivateKey, publicKey := keyFunc(t)
				oidcServer = utilsoidc.BuildAndRunTestServer(t, caFilePath, caKeyFilePath, "")

				apiServer = startTestAPIServerForOIDC(t, apiServerOIDCConfig{oidcURL: oidcServer.URL(), oidcClientID: defaultOIDCClientID,
					oidcCAFilePath: caFilePath, oidcUsernamePrefix: defaultOIDCUsernamePrefix, oidcUsernameClaim: "user"}, &signingPrivateKey.PublicKey)
				oidcServer.JwksHandler().EXPECT().KeySet().RunAndReturn(utilsoidc.DefaultJwksHandlerBehavior(t, publicKey)).Maybe()

				adminClient := kubernetes.NewForConfigOrDie(apiServer.ClientConfig)
				configureRBAC(t, adminClient, defaultRole, defaultRoleBinding)

				return oidcServer, apiServer, signingPrivateKey, caCertContent, caFilePath
			}, configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				idTokenLifetime := time.Second * 1200
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					// This asserts the minimum valid claims for an ID token required by the authenticator.
					// "iss", "aud", "exp" and a claim for the username.
					map[string]interface{}{
						"iss":  oidcServer.URL(),
						"user": defaultOIDCClaimedUsername,
						"aud":  defaultOIDCClientID,
						"exp":  time.Now().Add(idTokenLifetime).Unix(),
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
			},
			configureClient: configureClientFetchingOIDCCredentials,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
		},
		{
			name: "ID token signature can not be verified due to wrong JWKs",
			configureInfrastructure: func(t *testing.T, _ authenticationConfigFunc, keyFunc func(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey)) (
				oidcServer *utilsoidc.TestServer,
				apiServer *kubeapiserverapptesting.TestServer,
				signingPrivateKey *rsa.PrivateKey,
				caCertContent []byte,
				caFilePath string,
			) {
				caCertContent, _, caFilePath, caKeyFilePath := generateCert(t)

				signingPrivateKey, _ = keyFunc(t)

				oidcServer = utilsoidc.BuildAndRunTestServer(t, caFilePath, caKeyFilePath, "")

				apiServer = startTestAPIServerForOIDC(t, apiServerOIDCConfig{oidcURL: oidcServer.URL(), oidcClientID: defaultOIDCClientID, oidcCAFilePath: caFilePath, oidcUsernamePrefix: defaultOIDCUsernamePrefix}, &signingPrivateKey.PublicKey)

				adminClient := kubernetes.NewForConfigOrDie(apiServer.ClientConfig)
				configureRBAC(t, adminClient, defaultRole, defaultRoleBinding)

				anotherSigningPrivateKey, _ := keyFunc(t)

				oidcServer.JwksHandler().EXPECT().KeySet().RunAndReturn(utilsoidc.DefaultJwksHandlerBehavior(t, &anotherSigningPrivateKey.PublicKey)).Maybe()

				return oidcServer, apiServer, signingPrivateKey, caCertContent, caFilePath
			},
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": defaultOIDCClaimedUsername,
						"aud": defaultOIDCClientID,
						"exp": time.Now().Add(time.Second * 1200).Unix(),
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
			name: "ID token is okay but username is empty",
			configureInfrastructure: func(t *testing.T, _ authenticationConfigFunc, keyFunc func(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey)) (
				oidcServer *utilsoidc.TestServer,
				apiServer *kubeapiserverapptesting.TestServer,
				signingPrivateKey *rsa.PrivateKey,
				caCertContent []byte,
				caFilePath string,
			) {
				caCertContent, _, caFilePath, caKeyFilePath := generateCert(t)

				signingPrivateKey, _ = keyFunc(t)

				oidcServer = utilsoidc.BuildAndRunTestServer(t, caFilePath, caKeyFilePath, "")

				apiServer = startTestAPIServerForOIDC(t, apiServerOIDCConfig{
					oidcURL: oidcServer.URL(), oidcClientID: defaultOIDCClientID, oidcCAFilePath: caFilePath, oidcUsernamePrefix: "-",
				},
					&signingPrivateKey.PublicKey)

				oidcServer.JwksHandler().EXPECT().KeySet().RunAndReturn(utilsoidc.DefaultJwksHandlerBehavior(t, &signingPrivateKey.PublicKey)).Maybe()

				return oidcServer, apiServer, signingPrivateKey, caCertContent, caFilePath
			},
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": "",
						"aud": defaultOIDCClientID,
						"exp": time.Now().Add(time.Second * 1200).Unix(),
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
			},
			configureClient: configureClientFetchingOIDCCredentials,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				// the claim based approach is still allowed to use empty usernames
				_ = assert.True(t, apierrors.IsForbidden(errorToCheck), errorToCheck) &&
					assert.Equal(
						t,
						`pods is forbidden: User "" cannot list resource "pods" in API group "" in the namespace "default"`,
						errorToCheck.Error(),
					)
			},
		},
		{
			name: "client has wrong CA",
			configureInfrastructure: func(t *testing.T, fn authenticationConfigFunc, keyFunc func(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey)) (
				oidcServer *utilsoidc.TestServer,
				apiServer *kubeapiserverapptesting.TestServer,
				signingPrivateKey *rsa.PrivateKey,
				caCertContent []byte,
				caFilePath string,
			) {
				oidcServer, apiServer, signingPrivateKey, caCertContent, caFilePath = configureTestInfrastructure(t, fn, keyFunc)

				tempDir := t.TempDir()
				wrongCertFilePath := filepath.Join(tempDir, "localhost_127.0.0.1_.crt")
				_, _, err := certutil.GenerateSelfSignedCertKeyWithFixtures("localhost", []net.IP{utilsnet.ParseIPSloppy("127.0.0.1")}, nil, tempDir)
				require.NoError(t, err)

				return oidcServer, apiServer, signingPrivateKey, caCertContent, wrongCertFilePath
			},
			configureOIDCServerBehaviour: func(t *testing.T, _ *utilsoidc.TestServer, _ *rsa.PrivateKey) {},
			configureClient:              configureClientWithEmptyIDToken,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				expectedErr := new(x509.UnknownAuthorityError)
				assert.ErrorAs(t, errorToCheck, expectedErr)
			},
		},
	} {
		t.Run(tt.name, singleTestRunner(legacyAuthConfigFn, rsaGenerateKey, tt))
	}

	// ECDSA variant.
	for _, tt := range commonECDSAOIDCTests() {
		t.Run("ECDSA/"+tt.name, singleTestRunner(legacyAuthConfigFn, ecdsaGenerateKey, tt))
	}

	// Tests sharing a single server (only token behavior differs).
	t.Run("shared", func(t *testing.T) {
		t.Parallel()
		oidcServer, apiServer, signingPrivateKey, caCert, caFilePath := configureTestInfrastructure(t, legacyAuthConfigFn, rsaGenerateKey)

		tokenURL, err := oidcServer.TokenURL()
		require.NoError(t, err)

		t.Run("ID token is expired", func(t *testing.T) {
			configureOIDCServerToReturnExpiredIDToken(t, 2, oidcServer, signingPrivateKey)
			client := configureClientFetchingOIDCCredentials(t, apiServer.ClientConfig, caCert, caFilePath, oidcServer.URL(), tokenURL)
			_, err := client.CoreV1().Pods(defaultNamespace).List(testContext(t), metav1.ListOptions{})
			assert.True(t, apierrors.IsUnauthorized(err), err)
		})

		t.Run("wrong client ID", func(t *testing.T) {
			oidcServer.TokenHandler().EXPECT().Token().Times(2).Return(handlers.Token{}, utilsoidc.ErrBadClientID)
			client := configureClientWithEmptyIDToken(t, apiServer.ClientConfig, caCert, caFilePath, oidcServer.URL(), tokenURL)
			_, err := client.CoreV1().Pods(defaultNamespace).List(testContext(t), metav1.ListOptions{})
			urlError, ok := err.(*url.Error)
			require.True(t, ok)
			assert.Equal(
				t,
				"failed to refresh token: oauth2: cannot fetch token: 400 Bad Request\nResponse: client ID is bad\n",
				urlError.Err.Error(),
			)
		})

		t.Run("refresh flow does not return ID Token", func(t *testing.T) {
			configureOIDCServerToReturnExpiredIDToken(t, 1, oidcServer, signingPrivateKey)
			oidcServer.TokenHandler().EXPECT().Token().Times(1).Return(handlers.Token{
				IDToken:      "",
				AccessToken:  defaultStubAccessToken,
				RefreshToken: defaultStubRefreshToken,
				ExpiresIn:    time.Now().Add(time.Second * 1200).Unix(),
			}, nil)
			client := configureClientFetchingOIDCCredentials(t, apiServer.ClientConfig, caCert, caFilePath, oidcServer.URL(), tokenURL)
			_, err := client.CoreV1().Pods(defaultNamespace).List(testContext(t), metav1.ListOptions{})
			expectedError := new(apierrors.StatusError)
			require.ErrorAs(t, err, &expectedError)
			assert.Equal(
				t,
				`pods is forbidden: User "system:anonymous" cannot list resource "pods" in API group "" in the namespace "default"`,
				err.Error(),
			)
		})
	})
}

func TestStructuredAuthenticationConfig(t *testing.T) {
	t.Log("Testing OIDC authenticator with authentication config")
	genericapiserver.SetHostnameFuncForTests("testAPIServerID")

	structuredFn := authenticationConfigFunc(func(t *testing.T, issuerURL, caCert string) string {
		return newAuthConfigBuilder(issuerURL, caCert).
			withUsernameClaim("sub", defaultOIDCUsernamePrefix).
			build()
	})

	// Tests that need their own server (custom infrastructure).
	for _, tt := range []singleTest[*rsa.PrivateKey, *rsa.PublicKey]{
		{
			name: "ID token is ok",
			configureInfrastructure: func(t *testing.T, _ authenticationConfigFunc, keyFunc func(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey)) (
				oidcServer *utilsoidc.TestServer,
				apiServer *kubeapiserverapptesting.TestServer,
				signingPrivateKey *rsa.PrivateKey,
				caCertContent []byte,
				caFilePath string,
			) {
				caCertContent, _, caFilePath, caKeyFilePath := generateCert(t)
				signingPrivateKey, publicKey := keyFunc(t)
				oidcServer = utilsoidc.BuildAndRunTestServer(t, caFilePath, caKeyFilePath, "")

				authenticationConfig := newAuthConfigBuilder(oidcServer.URL(), string(caCertContent)).
					withUsernameClaim("user", defaultOIDCUsernamePrefix).
					build()
				apiServer = startTestAPIServerForOIDC(t, apiServerOIDCConfig{authenticationConfigYAML: authenticationConfig}, &signingPrivateKey.PublicKey)
				oidcServer.JwksHandler().EXPECT().KeySet().RunAndReturn(utilsoidc.DefaultJwksHandlerBehavior(t, publicKey)).Maybe()

				adminClient := kubernetes.NewForConfigOrDie(apiServer.ClientConfig)
				configureRBAC(t, adminClient, defaultRole, defaultRoleBinding)

				return oidcServer, apiServer, signingPrivateKey, caCertContent, caFilePath
			}, configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				idTokenLifetime := time.Second * 1200
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					// This asserts the minimum valid claims for an ID token required by the authenticator.
					// "iss", "aud", "exp" and a claim for the username.
					map[string]interface{}{
						"iss":  oidcServer.URL(),
						"user": defaultOIDCClaimedUsername,
						"aud":  defaultOIDCClientID,
						"exp":  time.Now().Add(idTokenLifetime).Unix(),
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
			},
			configureClient: configureClientFetchingOIDCCredentials,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				assert.NoError(t, errorToCheck)
			},
		},
		{
			name: "ID token signature can not be verified due to wrong JWKs",
			configureInfrastructure: func(t *testing.T, _ authenticationConfigFunc, keyFunc func(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey)) (
				oidcServer *utilsoidc.TestServer,
				apiServer *kubeapiserverapptesting.TestServer,
				signingPrivateKey *rsa.PrivateKey,
				caCertContent []byte,
				caFilePath string,
			) {
				caCertContent, _, caFilePath, caKeyFilePath := generateCert(t)

				signingPrivateKey, _ = keyFunc(t)

				oidcServer = utilsoidc.BuildAndRunTestServer(t, caFilePath, caKeyFilePath, "")

				authenticationConfig := newAuthConfigBuilder(oidcServer.URL(), string(caCertContent)).
					withUsernameClaim("sub", defaultOIDCUsernamePrefix).
					build()
				apiServer = startTestAPIServerForOIDC(t, apiServerOIDCConfig{authenticationConfigYAML: authenticationConfig}, &signingPrivateKey.PublicKey)

				adminClient := kubernetes.NewForConfigOrDie(apiServer.ClientConfig)
				configureRBAC(t, adminClient, defaultRole, defaultRoleBinding)

				anotherSigningPrivateKey, _ := keyFunc(t)

				oidcServer.JwksHandler().EXPECT().KeySet().RunAndReturn(utilsoidc.DefaultJwksHandlerBehavior(t, &anotherSigningPrivateKey.PublicKey)).Maybe()

				return oidcServer, apiServer, signingPrivateKey, caCertContent, caFilePath
			},
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": defaultOIDCClaimedUsername,
						"aud": defaultOIDCClientID,
						"exp": time.Now().Add(time.Second * 1200).Unix(),
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
			name: "ID token is okay but username is empty",
			configureInfrastructure: func(t *testing.T, _ authenticationConfigFunc, keyFunc func(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey)) (
				oidcServer *utilsoidc.TestServer,
				apiServer *kubeapiserverapptesting.TestServer,
				signingPrivateKey *rsa.PrivateKey,
				caCertContent []byte,
				caFilePath string,
			) {
				caCertContent, _, caFilePath, caKeyFilePath := generateCert(t)

				signingPrivateKey, _ = keyFunc(t)

				oidcServer = utilsoidc.BuildAndRunTestServer(t, caFilePath, caKeyFilePath, "")

				authenticationConfig := newAuthConfigBuilder(oidcServer.URL(), string(caCertContent)).
					withUsernameExpression("claims.sub").
					build()
				apiServer = startTestAPIServerForOIDC(t, apiServerOIDCConfig{authenticationConfigYAML: authenticationConfig}, &signingPrivateKey.PublicKey)

				oidcServer.JwksHandler().EXPECT().KeySet().RunAndReturn(utilsoidc.DefaultJwksHandlerBehavior(t, &signingPrivateKey.PublicKey)).Maybe()

				return oidcServer, apiServer, signingPrivateKey, caCertContent, caFilePath
			},
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": "",
						"aud": defaultOIDCClientID,
						"exp": time.Now().Add(time.Second * 1200).Unix(),
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
			name: "client has wrong CA",
			configureInfrastructure: func(t *testing.T, fn authenticationConfigFunc, keyFunc func(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey)) (
				oidcServer *utilsoidc.TestServer,
				apiServer *kubeapiserverapptesting.TestServer,
				signingPrivateKey *rsa.PrivateKey,
				caCertContent []byte,
				caFilePath string,
			) {
				oidcServer, apiServer, signingPrivateKey, caCertContent, caFilePath = configureTestInfrastructure(t, fn, keyFunc)

				tempDir := t.TempDir()
				wrongCertFilePath := filepath.Join(tempDir, "localhost_127.0.0.1_.crt")
				_, _, err := certutil.GenerateSelfSignedCertKeyWithFixtures("localhost", []net.IP{utilsnet.ParseIPSloppy("127.0.0.1")}, nil, tempDir)
				require.NoError(t, err)

				return oidcServer, apiServer, signingPrivateKey, caCertContent, wrongCertFilePath
			},
			configureOIDCServerBehaviour: func(t *testing.T, _ *utilsoidc.TestServer, _ *rsa.PrivateKey) {},
			configureClient:              configureClientWithEmptyIDToken,
			assertErrFn: func(t *testing.T, errorToCheck error) {
				expectedErr := new(x509.UnknownAuthorityError)
				assert.ErrorAs(t, errorToCheck, expectedErr)
			},
		},
	} {
		t.Run(tt.name, singleTestRunner(structuredFn, rsaGenerateKey, tt))
	}

	// ECDSA variant.
	for _, tt := range commonECDSAOIDCTests() {
		t.Run("ECDSA/"+tt.name, singleTestRunner(structuredFn, ecdsaGenerateKey, tt))
	}

	// Tests sharing a single server (only token behavior differs).
	t.Run("shared", func(t *testing.T) {
		t.Parallel()
		oidcServer, apiServer, signingPrivateKey, caCert, caFilePath := configureTestInfrastructure(t, structuredFn, rsaGenerateKey)

		tokenURL, err := oidcServer.TokenURL()
		require.NoError(t, err)

		t.Run("ID token is expired", func(t *testing.T) {
			configureOIDCServerToReturnExpiredIDToken(t, 2, oidcServer, signingPrivateKey)
			client := configureClientFetchingOIDCCredentials(t, apiServer.ClientConfig, caCert, caFilePath, oidcServer.URL(), tokenURL)
			_, err := client.CoreV1().Pods(defaultNamespace).List(testContext(t), metav1.ListOptions{})
			assert.True(t, apierrors.IsUnauthorized(err), err)
		})

		t.Run("wrong client ID", func(t *testing.T) {
			oidcServer.TokenHandler().EXPECT().Token().Times(2).Return(handlers.Token{}, utilsoidc.ErrBadClientID)
			client := configureClientWithEmptyIDToken(t, apiServer.ClientConfig, caCert, caFilePath, oidcServer.URL(), tokenURL)
			_, err := client.CoreV1().Pods(defaultNamespace).List(testContext(t), metav1.ListOptions{})
			urlError, ok := err.(*url.Error)
			require.True(t, ok)
			assert.Equal(
				t,
				"failed to refresh token: oauth2: cannot fetch token: 400 Bad Request\nResponse: client ID is bad\n",
				urlError.Err.Error(),
			)
		})

		t.Run("refresh flow does not return ID Token", func(t *testing.T) {
			configureOIDCServerToReturnExpiredIDToken(t, 1, oidcServer, signingPrivateKey)
			oidcServer.TokenHandler().EXPECT().Token().Times(1).Return(handlers.Token{
				IDToken:      "",
				AccessToken:  defaultStubAccessToken,
				RefreshToken: defaultStubRefreshToken,
				ExpiresIn:    time.Now().Add(time.Second * 1200).Unix(),
			}, nil)
			client := configureClientFetchingOIDCCredentials(t, apiServer.ClientConfig, caCert, caFilePath, oidcServer.URL(), tokenURL)
			_, err := client.CoreV1().Pods(defaultNamespace).List(testContext(t), metav1.ListOptions{})
			expectedError := new(apierrors.StatusError)
			require.ErrorAs(t, err, &expectedError)
			assert.Equal(
				t,
				`pods is forbidden: User "system:anonymous" cannot list resource "pods" in API group "" in the namespace "default"`,
				err.Error(),
			)
		})
	})
}

// legacyAuthConfigFn signals configureTestInfrastructure to use --oidc-* flags.
func legacyAuthConfigFn(_ *testing.T, _, _ string) string { return "" }

// commonECDSAOIDCTests returns ECDSA test entries that work identically in both modes.
func commonECDSAOIDCTests() []singleTest[*ecdsa.PrivateKey, *ecdsa.PublicKey] {
	return []singleTest[*ecdsa.PrivateKey, *ecdsa.PublicKey]{
		{
			name:                    "ID token is ok",
			configureInfrastructure: configureTestInfrastructure[*ecdsa.PrivateKey, *ecdsa.PublicKey],
			configureOIDCServerBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *ecdsa.PrivateKey) {
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
		},
	}
}

type singleTest[K utilsoidc.JosePrivateKey, L utilsoidc.JosePublicKey] struct {
	name                    string
	configureInfrastructure func(t *testing.T, fn authenticationConfigFunc, keyFunc func(t *testing.T) (K, L)) (
		oidcServer *utilsoidc.TestServer,
		apiServer *kubeapiserverapptesting.TestServer,
		signingPrivateKey K,
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
}

func singleTestRunner[K utilsoidc.JosePrivateKey, L utilsoidc.JosePublicKey](
	fn authenticationConfigFunc,
	keyFunc func(t *testing.T) (K, L),
	tt singleTest[K, L],
) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		oidcServer, apiServer, signingPrivateKey, caCert, certPath := tt.configureInfrastructure(t, fn, keyFunc)

		tt.configureOIDCServerBehaviour(t, oidcServer, signingPrivateKey)

		tokenURL, err := oidcServer.TokenURL()
		require.NoError(t, err)

		client := tt.configureClient(t, apiServer.ClientConfig, caCert, certPath, oidcServer.URL(), tokenURL)

		ctx := testContext(t)
		_, err = client.CoreV1().Pods(defaultNamespace).List(ctx, metav1.ListOptions{})

		tt.assertErrFn(t, err)
	}
}

func TestUpdatingRefreshTokenInCaseOfExpiredIDToken(t *testing.T) {
	t.Parallel()

	type testRun[K utilsoidc.JosePrivateKey] struct {
		name                            string
		configureUpdatingTokenBehaviour func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey K)
		assertErrFn                     func(t *testing.T, errorToCheck error)
	}

	var tests = []testRun[*rsa.PrivateKey]{
		{
			name: "cache returns stale client if refresh token is not updated in config",
			configureUpdatingTokenBehaviour: func(t *testing.T, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
				oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
					t,
					signingPrivateKey,
					map[string]interface{}{
						"iss": oidcServer.URL(),
						"sub": defaultOIDCClaimedUsername,
						"aud": defaultOIDCClientID,
						"exp": time.Now().Add(time.Second * 1200).Unix(),
					},
					defaultStubAccessToken,
					defaultStubRefreshToken,
				)).Times(1)
				configureOIDCServerToReturnExpiredRefreshTokenErrorOnTryingToUpdateIDToken(oidcServer)
			},
			assertErrFn: func(t *testing.T, errorToCheck error) {
				urlError, ok := errorToCheck.(*url.Error)
				require.True(t, ok)
				assert.Equal(
					t,
					"failed to refresh token: oauth2: cannot fetch token: 400 Bad Request\nResponse: refresh token is expired\n",
					urlError.Err.Error(),
				)
			},
		},
	}

	oidcServer, apiServer, signingPrivateKey, caCert, certPath := configureTestInfrastructure(t, func(t *testing.T, _, _ string) string { return "" }, rsaGenerateKey)

	tokenURL, err := oidcServer.TokenURL()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiredIDToken, stubRefreshToken := fetchExpiredToken(t, oidcServer, caCert, signingPrivateKey)
			clientConfig := configureClientConfigForOIDC(t, apiServer.ClientConfig, defaultOIDCClientID, certPath, expiredIDToken, stubRefreshToken, oidcServer.URL())
			expiredClient := kubernetes.NewForConfigOrDie(clientConfig)
			configureOIDCServerToReturnExpiredRefreshTokenErrorOnTryingToUpdateIDToken(oidcServer)

			ctx := testContext(t)
			_, err = expiredClient.CoreV1().Pods(defaultNamespace).List(ctx, metav1.ListOptions{})
			require.Error(t, err)

			tt.configureUpdatingTokenBehaviour(t, oidcServer, signingPrivateKey)
			idToken, stubRefreshToken := fetchOIDCCredentials(t, tokenURL, caCert)
			clientConfig = configureClientConfigForOIDC(t, apiServer.ClientConfig, defaultOIDCClientID, certPath, idToken, stubRefreshToken, oidcServer.URL())
			expectedOkClient := kubernetes.NewForConfigOrDie(clientConfig)
			_, err = expectedOkClient.CoreV1().Pods(defaultNamespace).List(ctx, metav1.ListOptions{})

			tt.assertErrFn(t, err)
		})
	}
}
