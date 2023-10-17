/*
Copyright 2015 The Kubernetes Authors.

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

/*
oidc implements the authenticator.Token interface using the OpenID Connect protocol.

	config := oidc.Options{
		IssuerURL:     "https://accounts.google.com",
		ClientID:      os.Getenv("GOOGLE_CLIENT_ID"),
		UsernameClaim: "email",
	}
	tokenAuthenticator, err := oidc.New(config)
*/
package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc"
	celgo "github.com/google/cel-go/cel"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/apis/apiserver"
	apiservervalidation "k8s.io/apiserver/pkg/apis/apiserver/validation"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	celenvironment "k8s.io/apiserver/pkg/cel/environment"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"
)

var (
	// synchronizeTokenIDVerifierForTest should be set to true to force a
	// wait until the token ID verifiers are ready.
	synchronizeTokenIDVerifierForTest = false
)

type Options struct {
	// JWTAuthenticator is the authenticator that will be used to verify the JWT.
	JWTAuthenticator apiserver.JWTAuthenticator
	// Optional KeySet to allow for synchronous initialization instead of fetching from the remote issuer.
	KeySet oidc.KeySet

	// PEM encoded root certificate contents of the provider.  Mutually exclusive with Client.
	CAContentProvider CAContentProvider

	// Optional http.Client used to make all requests to the remote issuer.  Mutually exclusive with CAContentProvider.
	Client *http.Client

	// SupportedSigningAlgs sets the accepted set of JOSE signing algorithms that
	// can be used by the provider to sign tokens.
	//
	// https://tools.ietf.org/html/rfc7518#section-3.1
	//
	// This value defaults to RS256, the value recommended by the OpenID Connect
	// spec:
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
	SupportedSigningAlgs []string

	// now is used for testing. It defaults to time.Now.
	now func() time.Time
}

// Subset of dynamiccertificates.CAContentProvider that can be used to dynamically load root CAs.
type CAContentProvider interface {
	CurrentCABundleContent() []byte
}

// initVerifier creates a new ID token verifier for the given configuration and issuer URL.  On success, calls setVerifier with the
// resulting verifier.
func initVerifier(ctx context.Context, config *oidc.Config, iss string) (*oidc.IDTokenVerifier, error) {
	provider, err := oidc.NewProvider(ctx, iss)
	if err != nil {
		return nil, fmt.Errorf("init verifier failed: %v", err)
	}
	return provider.Verifier(config), nil
}

// asyncIDTokenVerifier is an ID token verifier that allows async initialization
// of the issuer check.  Must be passed by reference as it wraps sync.Mutex.
type asyncIDTokenVerifier struct {
	m sync.Mutex

	// v is the ID token verifier initialized asynchronously.  It remains nil
	// up until it is eventually initialized.
	// Guarded by m
	v *oidc.IDTokenVerifier
}

// newAsyncIDTokenVerifier creates a new asynchronous token verifier.  The
// verifier is available immediately, but may remain uninitialized for some time
// after creation.
func newAsyncIDTokenVerifier(ctx context.Context, c *oidc.Config, iss string) *asyncIDTokenVerifier {
	t := &asyncIDTokenVerifier{}

	sync := make(chan struct{})
	// Polls indefinitely in an attempt to initialize the distributed claims
	// verifier, or until context canceled.
	initFn := func() (done bool, err error) {
		klog.V(4).Infof("oidc authenticator: attempting init: iss=%v", iss)
		v, err := initVerifier(ctx, c, iss)
		if err != nil {
			klog.Errorf("oidc authenticator: async token verifier for issuer: %q: %v", iss, err)
			return false, nil
		}
		t.m.Lock()
		defer t.m.Unlock()
		t.v = v
		close(sync)
		return true, nil
	}

	go func() {
		if done, _ := initFn(); !done {
			go wait.PollUntil(time.Second*10, initFn, ctx.Done())
		}
	}()

	if synchronizeTokenIDVerifierForTest {
		<-sync
	}

	return t
}

// verifier returns the underlying ID token verifier, or nil if one is not yet initialized.
func (a *asyncIDTokenVerifier) verifier() *oidc.IDTokenVerifier {
	a.m.Lock()
	defer a.m.Unlock()
	return a.v
}

type Authenticator struct {
	jwtAuthenticator apiserver.JWTAuthenticator

	// Contains an *oidc.IDTokenVerifier. Do not access directly use the
	// idTokenVerifier method.
	verifier atomic.Value

	cancel context.CancelFunc

	// resolver is used to resolve distributed claims.
	resolver *claimResolver

	// usernameMapper contains the compiled CEL expression for mapping the username
	// from the claims.
	// The expression must return a string value.
	usernameMapper *celMapper
	// groupMapper contains the compiled CEL expression for mapping the groups
	// from the claims.
	// The expression must return a string or a list of strings.
	groupMapper *celMapper
	// uidMapper contains the compiled CEL expression for mapping the uid
	// from the claims.
	// The expression must return a string value.
	uidMapper *celMapper

	// claimValidationRulesMapper contains the compiled CEL expression for validating the claims.
	// The expression must return a boolean value.
	claimValidationRulesMapper *celMapper

	// requiredClaims contains the list of claims that must be present in the token.
	requiredClaims map[string]string

	// userValidationRulesMapper contains the compiled CEL expression for validating the user info.
	// The expression must return a boolean value.
	userValidationRulesMapper *celMapper

	// extraMapper contains the compiled CEL expression for extra claim mappings.
	// The expression must return a string or a list of strings.
	extraMapper *celMapper
}

func (a *Authenticator) setVerifier(v *oidc.IDTokenVerifier) {
	a.verifier.Store(v)
}

func (a *Authenticator) idTokenVerifier() (*oidc.IDTokenVerifier, bool) {
	if v := a.verifier.Load(); v != nil {
		return v.(*oidc.IDTokenVerifier), true
	}
	return nil, false
}

func (a *Authenticator) Close() {
	a.cancel()
}

// whitelist of signing algorithms to ensure users don't mistakenly pass something
// goofy.
var allowedSigningAlgs = map[string]bool{
	oidc.RS256: true,
	oidc.RS384: true,
	oidc.RS512: true,
	oidc.ES256: true,
	oidc.ES384: true,
	oidc.ES512: true,
	oidc.PS256: true,
	oidc.PS384: true,
	oidc.PS512: true,
}

func New(opts Options) (*Authenticator, error) {
	if err := apiservervalidation.ValidateJWTAuthenticator(opts.JWTAuthenticator).ToAggregate(); err != nil {
		return nil, err
	}

	supportedSigningAlgs := opts.SupportedSigningAlgs
	if len(supportedSigningAlgs) == 0 {
		// RS256 is the default recommended by OpenID Connect and an 'alg' value
		// providers are required to implement.
		supportedSigningAlgs = []string{oidc.RS256}
	}
	for _, alg := range supportedSigningAlgs {
		if !allowedSigningAlgs[alg] {
			return nil, fmt.Errorf("oidc: unsupported signing alg: %q", alg)
		}
	}

	if opts.Client != nil && opts.CAContentProvider != nil {
		return nil, fmt.Errorf("oidc: Client and CAContentProvider are mutually exclusive")
	}

	client := opts.Client

	if client == nil {
		var roots *x509.CertPool
		var err error
		if opts.CAContentProvider != nil {
			// TODO(enj): make this reload CA data dynamically
			roots, err = certutil.NewPoolFromBytes(opts.CAContentProvider.CurrentCABundleContent())
			if err != nil {
				return nil, fmt.Errorf("Failed to read the CA contents: %v", err)
			}
		} else {
			klog.Info("OIDC: No x509 certificates provided, will use host's root CA set")
		}

		// Copied from http.DefaultTransport.
		tr := net.SetTransportDefaults(&http.Transport{
			// According to golang's doc, if RootCAs is nil,
			// TLS uses the host's root CA set.
			TLSClientConfig: &tls.Config{RootCAs: roots},
		})

		client = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	}

	ctx, cancel := context.WithCancel(context.Background())
	ctx = oidc.ClientContext(ctx, client)

	now := opts.now
	if now == nil {
		now = time.Now
	}

	verifierConfig := &oidc.Config{
		// The oidc config only supports a single audience, but we support multiple
		// audiences in the JWTAuthenticator.  We'll verify the audience ourselves
		// using validateAudience.
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: supportedSigningAlgs,
		Now:                  now,
	}

	var resolver *claimResolver
	groupsClaim := opts.JWTAuthenticator.ClaimMappings.Groups.Claim
	if groupsClaim != "" {
		resolver = newClaimResolver(groupsClaim, client, verifierConfig, opts.JWTAuthenticator.Issuer.Audiences)
	}

	authenticator := &Authenticator{
		jwtAuthenticator: opts.JWTAuthenticator,
		cancel:           cancel,
		resolver:         resolver,
	}

	if opts.KeySet != nil {
		// We already have a key set, synchronously initialize the verifier.
		authenticator.setVerifier(oidc.NewVerifier(opts.JWTAuthenticator.Issuer.URL, opts.KeySet, verifierConfig))
	} else {
		// Asynchronously attempt to initialize the authenticator. This enables
		// self-hosted providers, providers that run on top of Kubernetes itself.
		go wait.PollImmediateUntil(10*time.Second, func() (done bool, err error) {
			provider, err := oidc.NewProvider(ctx, opts.JWTAuthenticator.Issuer.URL)
			if err != nil {
				klog.Errorf("oidc authenticator: initializing plugin: %v", err)
				return false, nil
			}

			verifier := provider.Verifier(verifierConfig)
			authenticator.setVerifier(verifier)
			return true, nil
		}, ctx.Done())
	}

	compiler := authenticationcel.NewCompiler(celenvironment.MustBaseEnvSet(version.MajorMinor(1, 28)))
	usernameExpression := opts.JWTAuthenticator.ClaimMappings.Username.Expression
	if usernameExpression != nil && len(*usernameExpression) > 0 {
		authenticator.usernameMapper = compile(
			compiler,
			[]authenticationcel.ExpressionAccessor{&authenticationcel.ClaimMappingCondition{Expression: *usernameExpression}},
			celenvironment.StoredExpressions,
		)
	}
	groupsExpression := opts.JWTAuthenticator.ClaimMappings.Groups.Expression
	if groupsExpression != nil && len(*groupsExpression) > 0 {
		authenticator.groupMapper = compile(
			compiler,
			[]authenticationcel.ExpressionAccessor{&authenticationcel.ClaimMappingCondition{Expression: *groupsExpression}},
			celenvironment.StoredExpressions,
		)
	}
	uidExpression := opts.JWTAuthenticator.ClaimMappings.UID.Expression
	if len(uidExpression) > 0 {
		authenticator.uidMapper = compile(
			compiler,
			[]authenticationcel.ExpressionAccessor{&authenticationcel.ClaimMappingCondition{Expression: uidExpression}},
			celenvironment.StoredExpressions,
		)
	}

	var claimValidationexpressionAccessors []authenticationcel.ExpressionAccessor
	requiredClaims := make(map[string]string)
	for _, claimValidationRule := range opts.JWTAuthenticator.ClaimValidationRules {
		if len(claimValidationRule.Expression) > 0 {
			claimValidationexpressionAccessors = append(claimValidationexpressionAccessors, &authenticationcel.ClaimValidationCondition{
				Expression: claimValidationRule.Expression,
				Message:    claimValidationRule.Message,
			})
		} else if len(claimValidationRule.Claim) > 0 {
			requiredClaims[claimValidationRule.Claim] = claimValidationRule.RequiredValue
		}
	}

	if len(claimValidationexpressionAccessors) > 0 {
		authenticator.claimValidationRulesMapper = compile(
			compiler,
			claimValidationexpressionAccessors,
			celenvironment.StoredExpressions,
		)
	}
	authenticator.requiredClaims = requiredClaims

	var extraExpressionAccessors []authenticationcel.ExpressionAccessor
	for _, extraClaimMapping := range opts.JWTAuthenticator.ClaimMappings.Extra {
		if len(extraClaimMapping.ValueExpression) > 0 {
			extraExpressionAccessors = append(extraExpressionAccessors, &authenticationcel.ExtraMappingCondition{
				Expression: extraClaimMapping.ValueExpression,
				Key:        extraClaimMapping.Key,
			})
		}
	}

	if len(extraExpressionAccessors) > 0 {
		authenticator.extraMapper = compile(
			compiler,
			extraExpressionAccessors,
			celenvironment.StoredExpressions,
		)
	}

	var userInfoExpressionAccessors []authenticationcel.ExpressionAccessor
	for _, userInfoValidationRule := range opts.JWTAuthenticator.UserValidationRules {
		if len(userInfoValidationRule.Rule) > 0 {
			userInfoExpressionAccessors = append(userInfoExpressionAccessors, &authenticationcel.UserInfoValidationCondition{
				Expression: userInfoValidationRule.Rule,
				Message:    userInfoValidationRule.Message,
			})
		}
	}

	if len(userInfoExpressionAccessors) > 0 {
		authenticator.userValidationRulesMapper = compile(
			compiler,
			userInfoExpressionAccessors,
			celenvironment.StoredExpressions,
		)
	}

	return authenticator, nil
}

// untrustedIssuer extracts an untrusted "iss" claim from the given JWT token,
// or returns an error if the token can not be parsed.  Since the JWT is not
// verified, the returned issuer should not be trusted.
func untrustedIssuer(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("error decoding token: %v", err)
	}
	claims := struct {
		// WARNING: this JWT is not verified. Do not trust these claims.
		Issuer string `json:"iss"`
	}{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("while unmarshaling token: %v", err)
	}
	// Coalesce the legacy GoogleIss with the new one.
	//
	// http://openid.net/specs/openid-connect-core-1_0.html#GoogleIss
	if claims.Issuer == "accounts.google.com" {
		return "https://accounts.google.com", nil
	}
	return claims.Issuer, nil
}

func hasCorrectIssuer(iss, tokenData string) bool {
	uiss, err := untrustedIssuer(tokenData)
	if err != nil {
		return false
	}
	if uiss != iss {
		return false
	}
	return true
}

// endpoint represents an OIDC distributed claims endpoint.
type endpoint struct {
	// URL to use to request the distributed claim.  This URL is expected to be
	// prefixed by one of the known issuer URLs.
	URL string `json:"endpoint,omitempty"`
	// AccessToken is the bearer token to use for access.  If empty, it is
	// not used.  Access token is optional per the OIDC distributed claims
	// specification.
	// See: http://openid.net/specs/openid-connect-core-1_0.html#DistributedExample
	AccessToken string `json:"access_token,omitempty"`
	// JWT is the container for aggregated claims.  Not supported at the moment.
	// See: http://openid.net/specs/openid-connect-core-1_0.html#AggregatedExample
	JWT string `json:"JWT,omitempty"`
}

// claimResolver expands distributed claims by calling respective claim source
// endpoints.
type claimResolver struct {
	// claim is the distributed claim that may be resolved.
	claim string

	// client is the to use for resolving distributed claims
	client *http.Client

	// config is the OIDC configuration used for resolving distributed claims.
	config *oidc.Config

	// verifierPerIssuer contains, for each issuer, the appropriate verifier to use
	// for this claim.  It is assumed that there will be very few entries in
	// this map.
	// Guarded by m.
	verifierPerIssuer map[string]*asyncIDTokenVerifier

	audiences []string

	m sync.Mutex
}

// newClaimResolver creates a new resolver for distributed claims.
func newClaimResolver(claim string, client *http.Client, config *oidc.Config, audiences []string) *claimResolver {
	return &claimResolver{claim: claim, client: client, config: config, verifierPerIssuer: map[string]*asyncIDTokenVerifier{}, audiences: audiences}
}

// Verifier returns either the verifier for the specified issuer, or error.
func (r *claimResolver) Verifier(iss string) (*oidc.IDTokenVerifier, error) {
	r.m.Lock()
	av := r.verifierPerIssuer[iss]
	if av == nil {
		// This lazy init should normally be very quick.
		// TODO: Make this context cancelable.
		ctx := oidc.ClientContext(context.Background(), r.client)
		av = newAsyncIDTokenVerifier(ctx, r.config, iss)
		r.verifierPerIssuer[iss] = av
	}
	r.m.Unlock()

	v := av.verifier()
	if v == nil {
		return nil, fmt.Errorf("verifier not initialized for issuer: %q", iss)
	}
	return v, nil
}

// expand extracts the distributed claims from claim names and claim sources.
// The extracted claim value is pulled up into the supplied claims.
//
// Distributed claims are of the form as seen below, and are defined in the
// OIDC Connect Core 1.0, section 5.6.2.
// See: https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims
//
//	{
//	  ... (other normal claims)...
//	  "_claim_names": {
//	    "groups": "src1"
//	  },
//	  "_claim_sources": {
//	    "src1": {
//	      "endpoint": "https://www.example.com",
//	      "access_token": "f005ba11"
//	    },
//	  },
//	}
func (r *claimResolver) expand(ctx context.Context, c claims) error {
	const (
		// The claim containing a map of endpoint references per claim.
		// OIDC Connect Core 1.0, section 5.6.2.
		claimNamesKey = "_claim_names"
		// The claim containing endpoint specifications.
		// OIDC Connect Core 1.0, section 5.6.2.
		claimSourcesKey = "_claim_sources"
	)

	_, ok := c[r.claim]
	if ok {
		// There already is a normal claim, skip resolving.
		return nil
	}
	names, ok := c[claimNamesKey]
	if !ok {
		// No _claim_names, no keys to look up.
		return nil
	}

	claimToSource := map[string]string{}
	if err := json.Unmarshal([]byte(names), &claimToSource); err != nil {
		return fmt.Errorf("oidc: error parsing distributed claim names: %v", err)
	}

	rawSources, ok := c[claimSourcesKey]
	if !ok {
		// Having _claim_names claim,  but no _claim_sources is not an expected
		// state.
		return fmt.Errorf("oidc: no claim sources")
	}

	var sources map[string]endpoint
	if err := json.Unmarshal([]byte(rawSources), &sources); err != nil {
		// The claims sources claim is malformed, this is not an expected state.
		return fmt.Errorf("oidc: could not parse claim sources: %v", err)
	}

	src, ok := claimToSource[r.claim]
	if !ok {
		// No distributed claim present.
		return nil
	}
	ep, ok := sources[src]
	if !ok {
		return fmt.Errorf("id token _claim_names contained a source %s missing in _claims_sources", src)
	}
	if ep.URL == "" {
		// This is maybe an aggregated claim (ep.JWT != "").
		return nil
	}
	return r.resolve(ctx, ep, c)
}

// resolve requests distributed claims from all endpoints passed in,
// and inserts the lookup results into allClaims.
func (r *claimResolver) resolve(ctx context.Context, endpoint endpoint, allClaims claims) error {
	// TODO: cache resolved claims.
	jwt, err := getClaimJWT(ctx, r.client, endpoint.URL, endpoint.AccessToken)
	if err != nil {
		return fmt.Errorf("while getting distributed claim %q: %v", r.claim, err)
	}
	untrustedIss, err := untrustedIssuer(jwt)
	if err != nil {
		return fmt.Errorf("getting untrusted issuer from endpoint %v failed for claim %q: %v", endpoint.URL, r.claim, err)
	}
	v, err := r.Verifier(untrustedIss)
	if err != nil {
		return fmt.Errorf("verifying untrusted issuer %v failed: %v", untrustedIss, err)
	}
	t, err := v.Verify(ctx, jwt)
	if err != nil {
		return fmt.Errorf("verify distributed claim token: %v", err)
	}
	if err := verifyAudience(v, t, r.audiences); err != nil {
		return err
	}
	var distClaims claims
	if err := t.Claims(&distClaims); err != nil {
		return fmt.Errorf("could not parse distributed claims for claim %v: %v", r.claim, err)
	}
	value, ok := distClaims[r.claim]
	if !ok {
		return fmt.Errorf("jwt returned by distributed claim endpoint %q did not contain claim: %v", endpoint.URL, r.claim)
	}
	allClaims[r.claim] = value
	return nil
}

func (a *Authenticator) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	if !hasCorrectIssuer(a.jwtAuthenticator.Issuer.URL, token) {
		return nil, false, nil
	}

	verifier, ok := a.idTokenVerifier()
	if !ok {
		return nil, false, fmt.Errorf("oidc: authenticator not initialized")
	}

	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, false, fmt.Errorf("oidc: verify token: %v", err)
	}
	if err := verifyAudience(verifier, idToken, a.jwtAuthenticator.Issuer.Audiences); err != nil {
		return nil, false, err
	}

	var c claims
	if err := idToken.Claims(&c); err != nil {
		return nil, false, fmt.Errorf("oidc: parse claims: %v", err)
	}
	if a.resolver != nil {
		if err := a.resolver.expand(ctx, c); err != nil {
			return nil, false, fmt.Errorf("oidc: could not expand distributed claims: %v", err)
		}
	}

	var username string
	if username, err = a.getUsername(ctx, c); err != nil {
		return nil, false, err
	}

	info := &user.DefaultInfo{Name: username}
	if info.Groups, err = a.getGroups(ctx, c); err != nil {
		return nil, false, err
	}

	// TODO(aramase): handle prefix when it is a CEL expression
	groupsPrefix := a.jwtAuthenticator.ClaimMappings.Groups.Prefix
	if groupsPrefix != nil && *groupsPrefix != "" {
		for i, group := range info.Groups {
			info.Groups[i] = *groupsPrefix + group
		}
	}

	if info.UID, err = a.getUID(ctx, c); err != nil {
		return nil, false, err
	}

	extra, err := a.getExtra(ctx, c)
	if err != nil {
		return nil, false, err
	}
	if len(extra) > 0 {
		info.Extra = extra
	}

	// check to ensure all required claims are present in the ID token and have matching values.
	for claim, value := range a.requiredClaims {
		if !c.hasClaim(claim) {
			return nil, false, fmt.Errorf("oidc: required claim %s not present in ID token", claim)
		}

		// NOTE: Only string values are supported as valid required claim values.
		var claimValue string
		if err := c.unmarshalClaim(claim, &claimValue); err != nil {
			return nil, false, fmt.Errorf("oidc: parse claim %s: %v", claim, err)
		}
		if claimValue != value {
			return nil, false, fmt.Errorf("oidc: required claim %s value does not match. Got = %s, want = %s", claim, claimValue, value)
		}
	}

	if a.claimValidationRulesMapper != nil {
		evalResult, err := a.claimValidationRulesMapper.eval(ctx, c, nil)
		if err != nil {
			return nil, false, fmt.Errorf("oidc: error evaluating claim validation expression: %v", err)
		}
		// TODO(aramase): should we return aggregate errors?
		for _, result := range evalResult {
			if result.Error != nil {
				return nil, false, fmt.Errorf("oidc: error evaluating claim validation expression: %v", result.Error)
			}
			if !result.EvalResult.Value().(bool) {
				claimValidationCondition := result.ExpressionAccessor.(*authenticationcel.ClaimValidationCondition)
				return nil, false, fmt.Errorf("oidc: claim validation expression failed: %v", claimValidationCondition.Message)
			}
		}
	}

	if a.userValidationRulesMapper != nil {
		userInfo := &authenticationv1.UserInfo{
			Extra:    make(map[string]authenticationv1.ExtraValue),
			Groups:   info.GetGroups(),
			UID:      info.GetUID(),
			Username: info.GetName(),
		}
		// Convert the extra information in the user object
		for key, val := range info.GetExtra() {
			userInfo.Extra[key] = authenticationv1.ExtraValue(val)
		}

		evalResult, err := a.userValidationRulesMapper.eval(ctx, nil, userInfo)
		if err != nil {
			return nil, false, fmt.Errorf("oidc: error evaluating user info validation rule: %v", err)
		}

		for _, result := range evalResult {
			if result.Error != nil {
				return nil, false, fmt.Errorf("oidc: error evaluating user info validation rule: %v", result.Error)
			}
			if !result.EvalResult.Value().(bool) {
				userInfoValidationCondition := result.ExpressionAccessor.(*authenticationcel.UserInfoValidationCondition)
				return nil, false, fmt.Errorf("oidc: user info validation rule failed: %v", userInfoValidationCondition.Message)
			}
		}
	}

	return &authenticator.Response{User: info}, true, nil
}

func (a *Authenticator) getUsername(ctx context.Context, c claims) (string, error) {
	if a.usernameMapper != nil {
		evalResults, err := a.usernameMapper.eval(ctx, c, nil)
		if err != nil {
			return "", fmt.Errorf("oidc: error evaluating username claim expression: %w", err)
		}
		evalResult := evalResults[0]
		if evalResult.Error != nil {
			return "", fmt.Errorf("oidc: error evaluating username claim expression: %w", evalResult.Error)
		}

		if evalResult.EvalResult.Type() != celgo.StringType {
			return "", fmt.Errorf("oidc: error evaluating username claim expression: %w", fmt.Errorf("username claim expression must return a string"))
		}

		return evalResult.EvalResult.Value().(string), nil
	}

	var username string
	usernameClaim := a.jwtAuthenticator.ClaimMappings.Username.Claim
	if err := c.unmarshalClaim(usernameClaim, &username); err != nil {
		return "", fmt.Errorf("oidc: parse username claims %q: %v", usernameClaim, err)
	}

	if usernameClaim == "email" {
		// If the email_verified claim is present, ensure the email is valid.
		// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
		if hasEmailVerified := c.hasClaim("email_verified"); hasEmailVerified {
			var emailVerified bool
			if err := c.unmarshalClaim("email_verified", &emailVerified); err != nil {
				return "", fmt.Errorf("oidc: parse 'email_verified' claim: %v", err)
			}

			// If the email_verified claim is present we have to verify it is set to `true`.
			if !emailVerified {
				return "", fmt.Errorf("oidc: email not verified")
			}
		}
	}

	userNamePrefix := a.jwtAuthenticator.ClaimMappings.Username.Prefix
	if userNamePrefix != nil && *userNamePrefix != "" {
		return *userNamePrefix + username, nil
	}
	return username, nil
}

func (a *Authenticator) getGroups(ctx context.Context, c claims) ([]string, error) {
	groupsClaim := a.jwtAuthenticator.ClaimMappings.Groups.Claim
	if len(groupsClaim) > 0 {
		if _, ok := c[groupsClaim]; ok {
			// Some admins want to use string claims like "role" as the group value.
			// Allow the group claim to be a single string instead of an array.
			//
			// See: https://github.com/kubernetes/kubernetes/issues/33290
			var groups stringOrArray
			if err := c.unmarshalClaim(groupsClaim, &groups); err != nil {
				return nil, fmt.Errorf("oidc: parse groups claim %q: %w", groupsClaim, err)
			}
			return []string(groups), nil
		}
	}

	if a.groupMapper == nil {
		return nil, nil
	}

	evalResults, err := a.groupMapper.eval(ctx, c, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: error evaluating group claim expression: %v", err)
	}

	evalResult := evalResults[0]
	if evalResult.Error != nil {
		return nil, fmt.Errorf("oidc: error evaluating group claim expression: %v", evalResult.Error)
	}

	switch evalResult.EvalResult.Type().TypeName() {
	case celgo.StringType.TypeName():
		return []string{evalResult.EvalResult.Value().(string)}, nil
	case celgo.ListType(nil).TypeName():
		out := evalResult.EvalResult.Value().([]interface{})
		groups := make([]string, len(out))
		for i, v := range out {
			groups[i] = v.(string)
		}
		return groups, nil
	case celgo.NullType.TypeName():
		return nil, nil
	default:
		return nil, fmt.Errorf("oidc: error evaluating group claim expression: %v", fmt.Errorf("group claim expression must return a string or a list of strings"))
	}
}

func (a *Authenticator) getUID(ctx context.Context, c claims) (string, error) {
	uidClaim := a.jwtAuthenticator.ClaimMappings.UID.Claim
	if len(uidClaim) > 0 {
		var uid string
		if err := c.unmarshalClaim(uidClaim, &uid); err != nil {
			return "", fmt.Errorf("oidc: parse uid claim %q: %w", uidClaim, err)
		}
		return uid, nil
	}

	if a.uidMapper == nil {
		return "", nil
	}

	evalResults, err := a.uidMapper.eval(ctx, c, nil)
	if err != nil {
		return "", fmt.Errorf("oidc: error evaluating uid claim expression: %w", err)
	}
	evalResult := evalResults[0]
	if evalResult.Error != nil {
		return "", fmt.Errorf("oidc: error evaluating uid claim expression: %w", evalResult.Error)
	}
	if evalResult.EvalResult.Type() != celgo.StringType {
		return "", fmt.Errorf("oidc: error evaluating uid claim expression: %w", fmt.Errorf("uid claim expression must return a string"))
	}

	return evalResult.EvalResult.Value().(string), nil
}

func (a *Authenticator) getExtra(ctx context.Context, c claims) (map[string][]string, error) {
	if a.extraMapper == nil {
		return nil, nil
	}

	extra := make(map[string][]string, len(a.extraMapper.compilationResults))

	evalResult, err := a.extraMapper.eval(ctx, c, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: error evaluating extra claim expression: %w", err)
	}

	for _, result := range evalResult {
		if result.Error != nil {
			return nil, fmt.Errorf("oidc: error evaluating extra claim expression: %w", result.Error)
		}
		extraMapping := result.ExpressionAccessor.(*authenticationcel.ExtraMappingCondition)

		var resultValue []string
		switch result.EvalResult.Type().TypeName() {
		case celgo.StringType.TypeName():
			out := result.EvalResult.Value().(string)
			if len(out) > 0 {
				resultValue = []string{result.EvalResult.Value().(string)}
			}
		case celgo.ListType(nil).TypeName():
			out := result.EvalResult.Value().([]interface{})
			resultValue = make([]string, len(out))
			for i, v := range out {
				resultValue[i] = v.(string)
			}
		case celgo.NullType.TypeName():
			continue
		default:
			return nil, fmt.Errorf("oidc: error evaluating extra claim expression: %w", fmt.Errorf("extra claim expression must return a string or a list of strings"))
		}

		if len(resultValue) == 0 {
			continue
		}
		// if the key already exists, append the new values to the existing values
		if _, ok := extra[extraMapping.Key]; ok {
			extra[extraMapping.Key] = append(extra[extraMapping.Key], []string(resultValue)...)
			continue
		}
		extra[extraMapping.Key] = []string(resultValue)
	}

	return extra, nil
}

// getClaimJWT gets a distributed claim JWT from url, using the supplied access
// token as bearer token.  If the access token is "", the authorization header
// will not be set.
// TODO: Allow passing in JSON hints to the IDP.
func getClaimJWT(ctx context.Context, client *http.Client, url, accessToken string) (string, error) {
	// TODO: Allow passing request body with configurable information.
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("while calling %v: %v", url, err)
	}
	if accessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", accessToken))
	}
	req = req.WithContext(ctx)
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	// Report non-OK status code as an error.
	if response.StatusCode < http.StatusOK || response.StatusCode > http.StatusIMUsed {
		return "", fmt.Errorf("error while getting distributed claim JWT: %v", response.Status)
	}
	responseBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("could not decode distributed claim response")
	}
	return string(responseBytes), nil
}

type stringOrArray []string

func (s *stringOrArray) UnmarshalJSON(b []byte) error {
	var a []string
	if err := json.Unmarshal(b, &a); err == nil {
		*s = a
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	*s = []string{str}
	return nil
}

type claims map[string]json.RawMessage

func (c claims) unmarshalClaim(name string, v interface{}) error {
	val, ok := c[name]
	if !ok {
		return fmt.Errorf("claim not present")
	}
	return json.Unmarshal([]byte(val), v)
}

func (c claims) hasClaim(name string) bool {
	if _, ok := c[name]; !ok {
		return false
	}
	return true
}

func verifyAudience(verifier *oidc.IDTokenVerifier, idToken *oidc.IDToken, audiences []string) error {
	// At least one of the entries in audiences must match the "aud" claim in the ID token.
	// See: http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

	if len(audiences) == 0 { // this should never happen since we check in validation
		return fmt.Errorf("oidc: invalid configuration, audiences must be provided")
	}

	for _, aud := range audiences {
		if contains(idToken.Audience, aud) {
			return nil
		}
	}

	return fmt.Errorf("oidc: expected audience %q, got %q", audiences, idToken.Audience)
}

func contains(sli []string, ele string) bool {
	for _, s := range sli {
		if s == ele {
			return true
		}
	}
	return false
}
