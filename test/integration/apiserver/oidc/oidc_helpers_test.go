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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
	kubeapiserverapptesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/test/integration/framework"
	utilsoidc "k8s.io/kubernetes/test/utils/oidc"
	"k8s.io/kubernetes/test/utils/oidc/handlers"
	utilsnet "k8s.io/utils/net"
)

const (
	defaultNamespace           = "default"
	defaultOIDCClientID        = "f403b682-603f-4ec9-b3e4-cf111ef36f7c"
	defaultOIDCClaimedUsername = "john_doe"
	defaultOIDCUsernamePrefix  = "k8s-"
	defaultRBACRoleName        = "developer-role"
	defaultRBACRoleBindingName = "developer-role-binding"

	defaultStubRefreshToken = "_fake_refresh_token_"
	defaultStubAccessToken  = "_fake_access_token_"

	rsaKeyBitSize = 2048

	testAPIServerIDHash = "sha256:3c607df3b2bf22c9d9f01d5314b4bbf411c48ef43ff44ff29b1d55b41367c795"
)

var (
	defaultRole = &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role"},
		ObjectMeta: metav1.ObjectMeta{Name: defaultRBACRoleName},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:         []string{"list"},
				Resources:     []string{"pods"},
				APIGroups:     []string{""},
				ResourceNames: []string{},
			},
		},
	}
	defaultRoleBinding = &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: defaultRBACRoleBindingName},
		Subjects: []rbacv1.Subject{
			{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     rbacv1.UserKind,
				Name:     defaultOIDCUsernamePrefix + defaultOIDCClaimedUsername,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     defaultRBACRoleName,
		},
	}
)

// authenticationConfigFunc is a function that returns a string representation of an authentication config.
type authenticationConfigFunc func(t *testing.T, issuerURL, caCert string) string

type apiServerOIDCConfig struct {
	oidcURL                  string
	oidcClientID             string
	oidcCAFilePath           string
	oidcUsernamePrefix       string
	oidcUsernameClaim        string
	authenticationConfigYAML string
	needsEgressProxyOnStart  bool
}

func rsaGenerateKey(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBitSize)
	require.NoError(t, err)

	return privateKey, &privateKey.PublicKey
}

func ecdsaGenerateKey(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return privateKey, &privateKey.PublicKey
}

func configureTestInfrastructure[K utilsoidc.JosePrivateKey, L utilsoidc.JosePublicKey](t *testing.T, fn authenticationConfigFunc, keyFunc func(t *testing.T) (K, L)) (
	oidcServer *utilsoidc.TestServer,
	apiServer *kubeapiserverapptesting.TestServer,
	signingPrivateKey K,
	caCertContent []byte,
	caFilePath string,
) {
	t.Helper()

	return configureTestInfrastructureAndEgressProxy[K, L](t, fn, keyFunc, false)
}

func configureTestInfrastructureWithEgressProxy[K utilsoidc.JosePrivateKey, L utilsoidc.JosePublicKey](t *testing.T, fn authenticationConfigFunc, keyFunc func(t *testing.T) (K, L)) (
	oidcServer *utilsoidc.TestServer,
	apiServer *kubeapiserverapptesting.TestServer,
	signingPrivateKey K,
	caCertContent []byte,
	caFilePath string,
) {
	t.Helper()

	return configureTestInfrastructureAndEgressProxy[K, L](t, fn, keyFunc, true)
}

func configureTestInfrastructureAndEgressProxy[K utilsoidc.JosePrivateKey, L utilsoidc.JosePublicKey](t *testing.T, fn authenticationConfigFunc, keyFunc func(t *testing.T) (K, L), needsEgressProxyOnStart bool) (
	oidcServer *utilsoidc.TestServer,
	apiServer *kubeapiserverapptesting.TestServer,
	signingPrivateKey K,
	caCertContent []byte,
	caFilePath string,
) {
	t.Helper()

	caCertContent, _, caFilePath, caKeyFilePath := generateCert(t)

	signingPrivateKey, publicKey := keyFunc(t)

	oidcServer = utilsoidc.BuildAndRunTestServer(t, caFilePath, caKeyFilePath, "")

	authenticationConfig := fn(t, oidcServer.URL(), string(caCertContent))
	if len(authenticationConfig) > 0 {
		apiServer = startTestAPIServerForOIDC(t, apiServerOIDCConfig{authenticationConfigYAML: authenticationConfig, needsEgressProxyOnStart: needsEgressProxyOnStart}, publicKey)
	} else {
		apiServer = startTestAPIServerForOIDC(t, apiServerOIDCConfig{oidcURL: oidcServer.URL(), oidcClientID: defaultOIDCClientID, oidcCAFilePath: caFilePath, oidcUsernamePrefix: defaultOIDCUsernamePrefix}, publicKey)
	}

	oidcServer.JwksHandler().EXPECT().KeySet().RunAndReturn(utilsoidc.DefaultJwksHandlerBehavior(t, publicKey)).Maybe()

	adminClient := kubernetes.NewForConfigOrDie(apiServer.ClientConfig)
	configureRBAC(t, adminClient, defaultRole, defaultRoleBinding)

	return oidcServer, apiServer, signingPrivateKey, caCertContent, caFilePath
}

func configureBasicTestInfrastructure[K utilsoidc.JosePrivateKey, L utilsoidc.JosePublicKey](t *testing.T, fn authenticationConfigFunc, keyFunc func(t *testing.T) (K, L)) (
	oidcServer *utilsoidc.TestServer,
	apiServer *kubeapiserverapptesting.TestServer,
	caCertContent []byte,
	caFilePath string,
) {
	t.Helper()

	oidcServer, apiServer, signingPrivateKey, caCertContent, caFilePath := configureTestInfrastructure(t, fn, keyFunc)

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
}

func configureBasicTestInfrastructureWithRSAKey(t *testing.T, fn authenticationConfigFunc) (
	oidcServer *utilsoidc.TestServer,
	apiServer *kubeapiserverapptesting.TestServer,
	caCertContent []byte,
	caFilePath string,
) {
	t.Helper()
	return configureBasicTestInfrastructure(t, fn, rsaGenerateKey)
}

func configureClientFetchingOIDCCredentials(t *testing.T, restCfg *rest.Config, caCert []byte, certPath, oidcServerURL, oidcServerTokenURL string) kubernetes.Interface {
	idToken, stubRefreshToken := fetchOIDCCredentials(t, oidcServerTokenURL, caCert)
	clientConfig := configureClientConfigForOIDC(t, restCfg, defaultOIDCClientID, certPath, idToken, stubRefreshToken, oidcServerURL)
	return kubernetes.NewForConfigOrDie(clientConfig)
}

func configureClientWithEmptyIDToken(t *testing.T, restCfg *rest.Config, _ []byte, certPath, oidcServerURL, _ string) kubernetes.Interface {
	emptyIDToken, stubRefreshToken := "", defaultStubRefreshToken
	clientConfig := configureClientConfigForOIDC(t, restCfg, defaultOIDCClientID, certPath, emptyIDToken, stubRefreshToken, oidcServerURL)
	return kubernetes.NewForConfigOrDie(clientConfig)
}

func configureRBAC(t *testing.T, clientset kubernetes.Interface, role *rbacv1.Role, binding *rbacv1.RoleBinding) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	_, err := clientset.RbacV1().Roles(defaultNamespace).Create(ctx, role, metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = clientset.RbacV1().RoleBindings(defaultNamespace).Create(ctx, binding, metav1.CreateOptions{})
	require.NoError(t, err)
}

func configureClientConfigForOIDC(t *testing.T, config *rest.Config, clientID, caFilePath, idToken, refreshToken, oidcServerURL string) *rest.Config {
	t.Helper()
	cfg := rest.AnonymousClientConfig(config)
	cfg.AuthProvider = &api.AuthProviderConfig{
		Name: "oidc",
		Config: map[string]string{
			"client-id":                 clientID,
			"id-token":                  idToken,
			"idp-issuer-url":            oidcServerURL,
			"idp-certificate-authority": caFilePath,
			"refresh-token":             refreshToken,
		},
	}

	return cfg
}

func startTestAPIServerForOIDC[L utilsoidc.JosePublicKey](t *testing.T, c apiServerOIDCConfig, publicKey L) *kubeapiserverapptesting.TestServer {
	t.Helper()

	var customFlags []string
	if len(c.authenticationConfigYAML) > 0 {
		customFlags = []string{fmt.Sprintf("--authentication-config=%s", writeTempFile(t, c.authenticationConfigYAML))}
		if c.needsEgressProxyOnStart {
			udsName := filepath.Join(t.TempDir(), "uds")
			ready := make(chan struct{})
			go runEgressProxy(t, udsName, ready)
			select {
			case <-ready:
				// egress proxy is ready
			case <-time.After(time.Minute):
				t.Fatalf("timeout waiting for uds server to start")
			}
			egressConfig := fmt.Sprintf(`
apiVersion: apiserver.k8s.io/v1beta1
kind: EgressSelectorConfiguration
egressSelections:
- name: cluster
  connection:
    proxyProtocol: HTTPConnect
    transport:
      uds:
        udsName: %s
`, udsName)
			customFlags = append(customFlags, fmt.Sprintf("--egress-selector-config-file=%s", writeTempFile(t, egressConfig)))
		}
	} else {
		customFlags = []string{
			fmt.Sprintf("--oidc-issuer-url=%s", c.oidcURL),
			fmt.Sprintf("--oidc-client-id=%s", c.oidcClientID),
			fmt.Sprintf("--oidc-ca-file=%s", c.oidcCAFilePath),
			fmt.Sprintf("--oidc-username-prefix=%s", c.oidcUsernamePrefix),
		}
		if len(c.oidcUsernameClaim) > 0 {
			customFlags = append(customFlags, fmt.Sprintf("--oidc-username-claim=%s", c.oidcUsernameClaim))
		}
		customFlags = append(customFlags, setSigningAlgs(publicKey)...)
	}
	customFlags = append(customFlags, "--authorization-mode=RBAC")

	server, err := kubeapiserverapptesting.StartTestServer(
		t,
		kubeapiserverapptesting.NewDefaultTestServerOptions(),
		customFlags,
		framework.SharedEtcd(),
	)
	require.NoError(t, err)

	t.Cleanup(server.TearDownFn)

	return &server
}

func setSigningAlgs[K utilsoidc.JoseKey](key K) []string {
	alg := utilsoidc.GetSignatureAlgorithm(key)
	return []string{
		fmt.Sprintf("--oidc-signing-algs=%s", alg),
	}
}

func fetchOIDCCredentials(t *testing.T, oidcTokenURL string, caCertContent []byte) (idToken, refreshToken string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, oidcTokenURL, http.NoBody)
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	ok := caPool.AppendCertsFromPEM(caCertContent)
	require.True(t, ok)

	client := http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caPool,
		},
	}}

	token := new(handlers.Token)

	resp, err := client.Do(req)
	require.NoError(t, err)

	err = json.NewDecoder(resp.Body).Decode(token)
	require.NoError(t, err)

	return token.IDToken, token.RefreshToken
}

func fetchExpiredToken(t *testing.T, oidcServer *utilsoidc.TestServer, caCertContent []byte, signingPrivateKey *rsa.PrivateKey) (expiredToken, stubRefreshToken string) {
	t.Helper()

	tokenURL, err := oidcServer.TokenURL()
	require.NoError(t, err)

	configureOIDCServerToReturnExpiredIDToken(t, 1, oidcServer, signingPrivateKey)
	expiredToken, stubRefreshToken = fetchOIDCCredentials(t, tokenURL, caCertContent)

	return expiredToken, stubRefreshToken
}

func configureOIDCServerToReturnExpiredIDToken(t *testing.T, returningExpiredTokenTimes int, oidcServer *utilsoidc.TestServer, signingPrivateKey *rsa.PrivateKey) {
	t.Helper()

	oidcServer.TokenHandler().EXPECT().Token().RunAndReturn(func() (handlers.Token, error) {
		token, err := utilsoidc.TokenHandlerBehaviorReturningPredefinedJWT(
			t,
			signingPrivateKey,
			map[string]interface{}{
				"iss": oidcServer.URL(),
				"sub": defaultOIDCClaimedUsername,
				"aud": defaultOIDCClientID,
				"exp": time.Now().Add(-time.Millisecond).Unix(),
			},
			defaultStubAccessToken,
			defaultStubRefreshToken,
		)()
		return token, err
	}).Times(returningExpiredTokenTimes)
}

func configureOIDCServerToReturnExpiredRefreshTokenErrorOnTryingToUpdateIDToken(oidcServer *utilsoidc.TestServer) {
	oidcServer.TokenHandler().EXPECT().Token().Times(2).Return(handlers.Token{}, utilsoidc.ErrRefreshTokenExpired)
}

func generateCert(t *testing.T) (cert, key []byte, certFilePath, keyFilePath string) {
	t.Helper()

	tempDir := t.TempDir()
	certFilePath = filepath.Join(tempDir, "localhost_127.0.0.1_.crt")
	keyFilePath = filepath.Join(tempDir, "localhost_127.0.0.1_.key")

	cert, key, err := certutil.GenerateSelfSignedCertKeyWithFixtures("localhost", []net.IP{utilsnet.ParseIPSloppy("127.0.0.1")}, nil, tempDir)
	require.NoError(t, err)

	return cert, key, certFilePath, keyFilePath
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	file, err := os.CreateTemp("", "oidc-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(file.Name()); err != nil {
			t.Fatal(err)
		}
	})
	if err := os.WriteFile(file.Name(), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return file.Name()
}

// indentCertificateAuthority indents the certificate authority to match
// the format of the generated authentication config.
func indentCertificateAuthority(caCert string) string {
	return strings.ReplaceAll(caCert, "\n", "\n        ")
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func getHash(data string) string {
	if len(data) == 0 {
		return ""
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(data)))
}

// fetchJWKSAndComputeHash fetches the JWKS from the given server URL using the provided CA certificate,
// and returns the hash of the keyset bytes (computed the same way as the authenticator does).
func fetchJWKSAndComputeHash(t *testing.T, serverURL string, caCertContent []byte) string {
	t.Helper()

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertContent)
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caCertPool},
		},
	}

	resp, err := httpClient.Get(serverURL + "/jwks")
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()

	keySetBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return getHash(string(keySetBytes))
}

// getMetrics fetches metrics from the API server and returns only metrics matching the given prefixes.
// Floating point values in metrics ending with "_seconds" are normalized to "FP" for consistent comparison.
// Results are sorted alphabetically.
func getMetrics(t *testing.T, ctx context.Context, adminClient *kubernetes.Clientset, prefixes ...string) []string {
	t.Helper()

	body, err := adminClient.RESTClient().Get().AbsPath("/metrics").DoRaw(ctx)
	require.NoError(t, err)

	var gotMetricStrings []string
	trimFP := regexp.MustCompile(`(.*)(} \d+\.\d+.*)`)
	for _, line := range strings.Split(string(body), "\n") {
		matched := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(line, prefix) {
				matched = true
				break
			}
		}
		if matched {
			if strings.Contains(line, "_seconds") {
				line = trimFP.ReplaceAllString(line, `$1`) + "} FP" // ignore floating point metric values
			}
			gotMetricStrings = append(gotMetricStrings, line)
		}
	}

	slices.Sort(gotMetricStrings)

	return gotMetricStrings
}

// ---------------------------------------------------------------------------
// authConfigBuilder – fluent builder for AuthenticationConfiguration YAML
// ---------------------------------------------------------------------------

type authConfigBuilder struct {
	issuers []issuerConfig
}

type issuerConfig struct {
	issuerURL, discoveryURL string
	audiences               []string
	audienceMatchPolicy     string
	certificateAuthority    string
	caCertEmptyExplicit     bool
	egressSelectorType      string
	username                usernameMapping
	groups, uid             string
	extra                   []extraMapping
	claimValidationRules    []validationRule
	userValidationRules     []validationRule
}

type usernameMapping struct {
	claim, expression, prefix string
}

type extraMapping struct {
	key, valueExpression string
}

type validationRule struct {
	expression, message string
}

// newAuthConfigBuilder creates a builder pre-configured with a single issuer,
// defaultOIDCClientID as the audience, and username expression "'k8s-' + claims.sub".
func newAuthConfigBuilder(issuerURL, caCert string) *authConfigBuilder {
	return &authConfigBuilder{
		issuers: []issuerConfig{
			{
				issuerURL:            issuerURL,
				audiences:            []string{defaultOIDCClientID},
				certificateAuthority: caCert,
				username:             usernameMapping{expression: "'k8s-' + claims.sub"},
			},
		},
	}
}

// newEmptyAuthConfig creates a builder with no jwt block.
func newEmptyAuthConfig() *authConfigBuilder {
	return &authConfigBuilder{}
}

// newMultiIssuerAuthConfig creates a builder with no issuers; use addIssuer to append them.
func newMultiIssuerAuthConfig() *authConfigBuilder {
	return &authConfigBuilder{}
}

func (b *authConfigBuilder) addIssuer(issuerURL, caCert string) *authConfigBuilder {
	b.issuers = append(b.issuers, issuerConfig{
		issuerURL:            issuerURL,
		certificateAuthority: caCert,
		username:             usernameMapping{expression: "'k8s-' + claims.sub"},
	})
	return b
}

func (b *authConfigBuilder) lastIssuer() *issuerConfig {
	return &b.issuers[len(b.issuers)-1]
}

func (b *authConfigBuilder) withAudiences(audiences ...string) *authConfigBuilder {
	b.lastIssuer().audiences = audiences
	return b
}

func (b *authConfigBuilder) withAudienceMatchPolicy(policy string) *authConfigBuilder {
	b.lastIssuer().audienceMatchPolicy = policy
	return b
}

func (b *authConfigBuilder) withUsernameExpression(expression string) *authConfigBuilder {
	b.lastIssuer().username = usernameMapping{expression: expression}
	return b
}

func (b *authConfigBuilder) withUsernameClaim(claim, prefix string) *authConfigBuilder {
	b.lastIssuer().username = usernameMapping{claim: claim, prefix: prefix}
	return b
}

func (b *authConfigBuilder) withGroupsExpression(expression string) *authConfigBuilder {
	b.lastIssuer().groups = expression
	return b
}

func (b *authConfigBuilder) withUIDExpression(expression string) *authConfigBuilder {
	b.lastIssuer().uid = expression
	return b
}

func (b *authConfigBuilder) withExtra(key, valueExpression string) *authConfigBuilder {
	iss := b.lastIssuer()
	iss.extra = append(iss.extra, extraMapping{key: key, valueExpression: valueExpression})
	return b
}

func (b *authConfigBuilder) withClaimValidationRule(expression, message string) *authConfigBuilder {
	iss := b.lastIssuer()
	iss.claimValidationRules = append(iss.claimValidationRules, validationRule{expression: expression, message: message})
	return b
}

func (b *authConfigBuilder) withUserValidationRule(expression, message string) *authConfigBuilder {
	iss := b.lastIssuer()
	iss.userValidationRules = append(iss.userValidationRules, validationRule{expression: expression, message: message})
	return b
}

func (b *authConfigBuilder) withEgressSelectorType(selectorType string) *authConfigBuilder {
	b.lastIssuer().egressSelectorType = selectorType
	return b
}

func (b *authConfigBuilder) withDiscoveryURL(url string) *authConfigBuilder {
	b.lastIssuer().discoveryURL = url
	return b
}

func (b *authConfigBuilder) withEmptyCertificateAuthority() *authConfigBuilder {
	iss := b.lastIssuer()
	iss.certificateAuthority = ""
	iss.caCertEmptyExplicit = true
	return b
}

func (b *authConfigBuilder) build() string {
	var sb strings.Builder
	sb.WriteString("\napiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\n")
	if len(b.issuers) == 0 {
		return sb.String()
	}
	sb.WriteString("jwt:\n")
	for _, iss := range b.issuers {
		sb.WriteString("- issuer:\n")
		sb.WriteString(fmt.Sprintf("    url: %s\n", iss.issuerURL))
		if iss.discoveryURL != "" {
			sb.WriteString(fmt.Sprintf("    discoveryURL: %s\n", iss.discoveryURL))
		}
		if iss.egressSelectorType != "" {
			sb.WriteString(fmt.Sprintf("    egressSelectorType: %s\n", iss.egressSelectorType))
		}
		sb.WriteString("    audiences:\n")
		for _, a := range iss.audiences {
			sb.WriteString(fmt.Sprintf("    - %s\n", a))
		}
		if iss.audienceMatchPolicy != "" {
			sb.WriteString(fmt.Sprintf("    audienceMatchPolicy: %s\n", iss.audienceMatchPolicy))
		}
		if iss.caCertEmptyExplicit {
			sb.WriteString("    certificateAuthority: \"\"\n")
		} else if iss.certificateAuthority != "" {
			sb.WriteString(fmt.Sprintf("    certificateAuthority: |\n        %s\n", indentCertificateAuthority(iss.certificateAuthority)))
		}
		sb.WriteString("  claimMappings:\n")
		sb.WriteString("    username:\n")
		if iss.username.expression != "" {
			sb.WriteString(fmt.Sprintf("      expression: \"%s\"\n", iss.username.expression))
		} else if iss.username.claim != "" {
			sb.WriteString(fmt.Sprintf("      claim: %s\n", iss.username.claim))
			sb.WriteString(fmt.Sprintf("      prefix: %s\n", iss.username.prefix))
		}
		if iss.groups != "" {
			sb.WriteString("    groups:\n")
			sb.WriteString(fmt.Sprintf("      expression: '%s'\n", iss.groups))
		}
		if iss.uid != "" {
			sb.WriteString("    uid:\n")
			sb.WriteString(fmt.Sprintf("      expression: \"%s\"\n", iss.uid))
		}
		if len(iss.extra) > 0 {
			sb.WriteString("    extra:\n")
			for _, e := range iss.extra {
				sb.WriteString(fmt.Sprintf("    - key: \"%s\"\n", e.key))
				sb.WriteString(fmt.Sprintf("      valueExpression: \"%s\"\n", e.valueExpression))
			}
		}
		if len(iss.claimValidationRules) > 0 {
			sb.WriteString("  claimValidationRules:\n")
			for _, r := range iss.claimValidationRules {
				sb.WriteString(fmt.Sprintf("  - expression: '%s'\n", r.expression))
				sb.WriteString(fmt.Sprintf("    message: '%s'\n", r.message))
			}
		}
		if len(iss.userValidationRules) > 0 {
			sb.WriteString("  userValidationRules:\n")
			for _, r := range iss.userValidationRules {
				sb.WriteString(fmt.Sprintf("  - expression: \"%s\"\n", r.expression))
				sb.WriteString(fmt.Sprintf("    message: \"%s\"\n", r.message))
			}
		}
	}
	return sb.String()
}
