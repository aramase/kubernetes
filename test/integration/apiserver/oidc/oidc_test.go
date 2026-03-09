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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/features"
	genericapiserver "k8s.io/apiserver/pkg/server"
	authenticationconfigmetrics "k8s.io/apiserver/pkg/server/options/authenticationconfig/metrics"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	kubeapiserverapptesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/pkg/kubeapiserver/options"
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

t.Run("client has wrong CA", func(t *testing.T) {
tempDir := t.TempDir()
wrongCertFilePath := filepath.Join(tempDir, "localhost_127.0.0.1_.crt")
_, _, err := certutil.GenerateSelfSignedCertKeyWithFixtures("localhost", []net.IP{utilsnet.ParseIPSloppy("127.0.0.1")}, nil, tempDir)
require.NoError(t, err)
client := configureClientWithEmptyIDToken(t, apiServer.ClientConfig, caCert, wrongCertFilePath, oidcServer.URL(), tokenURL)
_, err = client.CoreV1().Pods(defaultNamespace).List(testContext(t), metav1.ListOptions{})
expectedErr := new(x509.UnknownAuthorityError)
assert.ErrorAs(t, err, expectedErr)
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

t.Run("client has wrong CA", func(t *testing.T) {
tempDir := t.TempDir()
wrongCertFilePath := filepath.Join(tempDir, "localhost_127.0.0.1_.crt")
_, _, err := certutil.GenerateSelfSignedCertKeyWithFixtures("localhost", []net.IP{utilsnet.ParseIPSloppy("127.0.0.1")}, nil, tempDir)
require.NoError(t, err)
client := configureClientWithEmptyIDToken(t, apiServer.ClientConfig, caCert, wrongCertFilePath, oidcServer.URL(), tokenURL)
_, err = client.CoreV1().Pods(defaultNamespace).List(testContext(t), metav1.ListOptions{})
expectedErr := new(x509.UnknownAuthorityError)
assert.ErrorAs(t, err, expectedErr)
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
				time.Sleep(options.UpdateAuthenticationConfigTimeout + hardCodedTokenCacheTTLAndPollInterval) // has to be longer than UpdateAuthenticationConfigTimeout
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

			oidcServer.JwksHandler().EXPECT().KeySet().RunAndReturn(utilsoidc.DefaultJwksHandlerBehavior(t, publicKey)).Maybe()

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

	oidcServer1.JwksHandler().EXPECT().KeySet().RunAndReturn(utilsoidc.DefaultJwksHandlerBehavior(t, publicKey1)).Maybe()
	oidcServer2.JwksHandler().EXPECT().KeySet().RunAndReturn(utilsoidc.DefaultJwksHandlerBehavior(t, publicKey2)).Maybe()

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

	oidcServer1.JwksHandler().EXPECT().KeySet().RunAndReturn(utilsoidc.DefaultJwksHandlerBehavior(t, publicKey1)).Maybe()
	oidcServer2.JwksHandler().EXPECT().KeySet().RunAndReturn(utilsoidc.DefaultJwksHandlerBehavior(t, publicKey2)).Maybe()

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
