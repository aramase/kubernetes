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

package validation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	api "k8s.io/apiserver/pkg/apis/apiserver"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/utils/pointer"
)

var (
	compiler = authenticationcel.NewCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))
)

func TestValidateAuthenticationConfiguration(t *testing.T) {
	testCases := []struct {
		name string
		in   *api.AuthenticationConfiguration
		want string
	}{
		{
			name: "duplicate issuer",
			in: &api.AuthenticationConfiguration{
				JWT: []api.JWTAuthenticator{
					{
						Issuer: api.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: api.ClaimMappings{
							Username: api.PrefixedClaimOrExpression{
								Claim:  "claim",
								Prefix: pointer.String("prefix"),
							},
						},
					},
					{
						Issuer: api.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
					},
				},
			},
			want: `jwt[1].issuer.url: Duplicate value: "https://issuer-url"`,
		},
		{
			name: "failed issuer validation",
			in: &api.AuthenticationConfiguration{
				JWT: []api.JWTAuthenticator{
					{
						Issuer: api.Issuer{
							URL:       "invalid-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: api.ClaimMappings{
							Username: api.PrefixedClaimOrExpression{
								Claim:  "claim",
								Prefix: pointer.String("prefix"),
							},
						},
					},
				},
			},
			want: `jwt[0].issuer.url: Invalid value: "invalid-url": URL scheme must be https`,
		},
		{
			name: "failed claimValidationRule validation",
			in: &api.AuthenticationConfiguration{
				JWT: []api.JWTAuthenticator{
					{
						Issuer: api.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []api.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
							{
								Claim:         "foo",
								RequiredValue: "baz",
							},
						},
						ClaimMappings: api.ClaimMappings{
							Username: api.PrefixedClaimOrExpression{
								Claim:  "claim",
								Prefix: pointer.String("prefix"),
							},
						},
					},
				},
			},
			want: `jwt[0].claimValidationRules[1].claim: Duplicate value: "foo"`,
		},
		{
			name: "failed claimMapping validation",
			in: &api.AuthenticationConfiguration{
				JWT: []api.JWTAuthenticator{
					{
						Issuer: api.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []api.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: api.ClaimMappings{
							Username: api.PrefixedClaimOrExpression{
								Prefix: pointer.String("prefix"),
							},
						},
					},
				},
			},
			want: "jwt[0].claimMappings.username: Required value: claim or expression is required",
		},
		{
			name: "failed userValidationRule validation",
			in: &api.AuthenticationConfiguration{
				JWT: []api.JWTAuthenticator{
					{
						Issuer: api.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []api.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: api.ClaimMappings{
							Username: api.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: pointer.String("prefix"),
							},
						},
						UserValidationRules: []api.UserValidationRule{
							{Rule: "user.username == 'foo'"},
							{Rule: "user.username == 'foo'"},
						},
					},
				},
			},
			want: `jwt[0].userValidationRules[1].rule: Duplicate value: "user.username == 'foo'"`,
		},
		{
			name: "valid authentication configuration",
			in: &api.AuthenticationConfiguration{
				JWT: []api.JWTAuthenticator{
					{
						Issuer: api.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []api.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: api.ClaimMappings{
							Username: api.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: pointer.String("prefix"),
							},
						},
					},
				},
			},
			want: "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateAuthenticationConfiguration(tt.in).ToAggregate()
			if d := cmp.Diff(tt.want, errString(got)); d != "" {
				t.Fatalf("AuthenticationConfiguration validation mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	fldPath := field.NewPath("issuer", "url")

	testCases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "url is empty",
			in:   "",
			want: "issuer.url: Required value: URL is required",
		},
		{
			name: "url parse error",
			in:   "https://issuer-url:invalid-port",
			want: `issuer.url: Invalid value: "https://issuer-url:invalid-port": parse "https://issuer-url:invalid-port": invalid port ":invalid-port" after host`,
		},
		{
			name: "url is not https",
			in:   "http://issuer-url",
			want: `issuer.url: Invalid value: "http://issuer-url": URL scheme must be https`,
		},
		{
			name: "url user info is not allowed",
			in:   "https://user:pass@issuer-url",
			want: `issuer.url: Invalid value: "https://user:pass@issuer-url": URL must not contain a username or password`,
		},
		{
			name: "url raw query is not allowed",
			in:   "https://issuer-url?query",
			want: `issuer.url: Invalid value: "https://issuer-url?query": URL must not contain a query`,
		},
		{
			name: "url fragment is not allowed",
			in:   "https://issuer-url#fragment",
			want: `issuer.url: Invalid value: "https://issuer-url#fragment": URL must not contain a fragment`,
		},
		{
			name: "valid url",
			in:   "https://issuer-url",
			want: "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := validateURL(tt.in, fldPath).ToAggregate()
			if d := cmp.Diff(tt.want, errString(got)); d != "" {
				t.Fatalf("URL validation mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestValidateAudiences(t *testing.T) {
	fldPath := field.NewPath("issuer", "audiences")

	testCases := []struct {
		name string
		in   []string
		want string
	}{
		{
			name: "audiences is empty",
			in:   []string{},
			want: "issuer.audiences: Required value: at least one issuer.audiences is required",
		},
		{
			name: "at most one audiences is allowed",
			in:   []string{"audience1", "audience2"},
			want: "issuer.audiences: Too many: 2: must have at most 1 items",
		},
		{
			name: "audience is empty",
			in:   []string{""},
			want: "issuer.audiences[0]: Required value: audience can't be empty",
		},
		{
			name: "valid audience",
			in:   []string{"audience"},
			want: "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := validateAudiences(tt.in, fldPath).ToAggregate()
			if d := cmp.Diff(tt.want, errString(got)); d != "" {
				t.Fatalf("Audiences validation mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestValidateCertificateAuthority(t *testing.T) {
	fldPath := field.NewPath("issuer", "certificateAuthority")

	testCases := []struct {
		name string
		in   func() string
		want string
	}{
		{
			name: "invalid certificate authority",
			in:   func() string { return "invalid" },
			want: `issuer.certificateAuthority: Invalid value: "<omitted>": data does not contain any valid RSA or ECDSA certificates`,
		},
		{
			name: "certificate authority is empty",
			in:   func() string { return "" },
			want: "",
		},
		{
			name: "valid certificate authority",
			in: func() string {
				caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				caCert, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "test-ca"}, caPrivateKey)
				if err != nil {
					t.Fatal(err)
				}
				return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
			},
			want: "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := validateCertificateAuthority(tt.in(), fldPath).ToAggregate()
			if d := cmp.Diff(tt.want, errString(got)); d != "" {
				t.Fatalf("CertificateAuthority validation mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestValidateClaimValidationRules(t *testing.T) {
	fldPath := field.NewPath("issuer", "claimValidationRules")

	testCases := []struct {
		name string
		in   []api.ClaimValidationRule
		want string
	}{
		{
			name: "claim and expression are empty",
			in:   []api.ClaimValidationRule{{}},
			want: "issuer.claimValidationRules[0].claim: Required value: claim or expression is required",
		},
		{
			name: "claim and expression are set",
			in: []api.ClaimValidationRule{
				{Claim: "claim", Expression: "expression"},
			},
			want: `issuer.claimValidationRules[0].claim: Invalid value: "claim": claim and expression can't both be set`,
		},
		{
			name: "message set when claim is set",
			in: []api.ClaimValidationRule{
				{Claim: "claim", Message: "message"},
			},
			want: `issuer.claimValidationRules[0].message: Invalid value: "message": message can't be set when claim is set`,
		},
		{
			name: "requiredValue set when expression is set",
			in: []api.ClaimValidationRule{
				{Expression: "claims.foo == 'bar'", RequiredValue: "value"},
			},
			want: `issuer.claimValidationRules[0].requiredValue: Invalid value: "value": requiredValue can't be set when expression is set`,
		},
		{
			name: "duplicate claim",
			in: []api.ClaimValidationRule{
				{Claim: "claim"},
				{Claim: "claim"},
			},
			want: `issuer.claimValidationRules[1].claim: Duplicate value: "claim"`,
		},
		{
			name: "duplicate expression",
			in: []api.ClaimValidationRule{
				{Expression: "claims.foo == 'bar'"},
				{Expression: "claims.foo == 'bar'"},
			},
			want: `issuer.claimValidationRules[1].expression: Duplicate value: "claims.foo == 'bar'"`,
		},
		{
			name: "valid claim validation rule with expression",
			in: []api.ClaimValidationRule{
				{Expression: "claims.foo == 'bar'"},
			},
			want: "",
		},
		{
			name: "valid claim validation rule with multiple rules",
			in: []api.ClaimValidationRule{
				{Claim: "claim1", RequiredValue: "value1"},
				{Claim: "claim2", RequiredValue: "value2"},
			},
			want: "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := validateClaimValidationRules(compiler, tt.in, fldPath).ToAggregate()
			if d := cmp.Diff(tt.want, errString(got)); d != "" {
				t.Fatalf("ClaimValidationRules validation mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestValidateClaimMappings(t *testing.T) {
	fldPath := field.NewPath("issuer", "claimMappings")

	testCases := []struct {
		name string
		in   api.ClaimMappings
		want string
	}{
		{
			name: "username expression and claim are set",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Claim:      "claim",
					Expression: pointer.String("claims.username"),
				},
			},
			want: `issuer.claimMappings.username: Invalid value: "": claim and expression can't both be set`,
		},
		{
			name: "username expression and claim are empty",
			in:   api.ClaimMappings{Username: api.PrefixedClaimOrExpression{}},
			want: "issuer.claimMappings.username: Required value: claim or expression is required",
		},
		{
			name: "username prefix set when expression is set",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Expression: pointer.String("claims.username"),
					Prefix:     pointer.String("prefix"),
				},
			},
			want: `issuer.claimMappings.username.prefix: Invalid value: "prefix": prefix can't be set when expression is set`,
		},
		{
			name: "username prefix is nil when claim is set",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Claim: "claim",
				},
			},
			want: `issuer.claimMappings.username.prefix: Required value: prefix is required when claim is set`,
		},
		{
			name: "username expression is invalid",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Expression: pointer.String("foo.bar"),
				},
			},
			want: `issuer.claimMappings.username.expression: Invalid value: "foo.bar": compilation failed: ERROR: <input>:1:1: undeclared reference to 'foo' (in container '')
 | foo.bar
 | ^`,
		},
		{
			name: "groups expression and claim are set",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Claim:  "claim",
					Prefix: pointer.String("prefix"),
				},
				Groups: api.PrefixedClaimOrExpression{
					Claim:      "claim",
					Expression: pointer.String("claims.groups"),
				},
			},
			want: `issuer.claimMappings.groups: Invalid value: "": claim and expression can't both be set`,
		},
		{
			name: "groups expression and claim are empty, but prefix is set",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Claim:  "claim",
					Prefix: pointer.String("prefix"),
				},
				Groups: api.PrefixedClaimOrExpression{
					Prefix: pointer.String("prefix"),
				},
			},
			want: `issuer.claimMappings.groups.prefix: Invalid value: "prefix": prefix can't be set when claim is not set`,
		},
		{
			name: "groups prefix set when expression is set",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Claim:  "claim",
					Prefix: pointer.String("prefix"),
				},
				Groups: api.PrefixedClaimOrExpression{
					Expression: pointer.String("claims.groups"),
					Prefix:     pointer.String("prefix"),
				},
			},
			want: `issuer.claimMappings.groups.prefix: Invalid value: "prefix": prefix can't be set when expression is set`,
		},
		{
			name: "groups prefix is nil when claim is set",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Claim:  "claim",
					Prefix: pointer.String("prefix"),
				},
				Groups: api.PrefixedClaimOrExpression{
					Claim: "claim",
				},
			},
			want: `issuer.claimMappings.groups.prefix: Required value: prefix is required when claim is set`,
		},
		{
			name: "groups expression is invalid",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Claim:  "claim",
					Prefix: pointer.String("prefix"),
				},
				Groups: api.PrefixedClaimOrExpression{
					Expression: pointer.String("foo.bar"),
				},
			},
			want: `issuer.claimMappings.groups.expression: Invalid value: "foo.bar": compilation failed: ERROR: <input>:1:1: undeclared reference to 'foo' (in container '')
 | foo.bar
 | ^`,
		},
		{
			name: "uid claim and expression are set",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Claim:  "claim",
					Prefix: pointer.String("prefix"),
				},
				UID: api.ClaimOrExpression{
					Claim:      "claim",
					Expression: "claims.uid",
				},
			},
			want: `issuer.claimMappings.uid: Invalid value: "": claim and expression can't both be set`,
		},
		{
			name: "uid expression is invalid",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Claim:  "claim",
					Prefix: pointer.String("prefix"),
				},
				UID: api.ClaimOrExpression{
					Expression: "foo.bar",
				},
			},
			want: `issuer.claimMappings.uid.expression: Invalid value: "foo.bar": compilation failed: ERROR: <input>:1:1: undeclared reference to 'foo' (in container '')
 | foo.bar
 | ^`,
		},
		{
			name: "extra mapping key is empty",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Claim:  "claim",
					Prefix: pointer.String("prefix"),
				},
				Extra: []api.ExtraMapping{
					{Key: "", ValueExpression: "claims.extra"},
				},
			},
			want: `issuer.claimMappings.extra[0].key: Required value: key is required`,
		},
		{
			name: "extra mapping value expression is empty",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Claim:  "claim",
					Prefix: pointer.String("prefix"),
				},
				Extra: []api.ExtraMapping{
					{Key: "key", ValueExpression: ""},
				},
			},
			want: `issuer.claimMappings.extra[0].valueExpression: Required value: valueExpression is required`,
		},
		{
			name: "extra mapping value expression is invalid",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{
					Claim:  "claim",
					Prefix: pointer.String("prefix"),
				},
				Extra: []api.ExtraMapping{
					{Key: "key", ValueExpression: "foo.bar"},
				},
			},
			want: `issuer.claimMappings.extra[0].valueExpression: Invalid value: "foo.bar": compilation failed: ERROR: <input>:1:1: undeclared reference to 'foo' (in container '')
 | foo.bar
 | ^`,
		},
		{
			name: "valid claim mappings",
			in: api.ClaimMappings{
				Username: api.PrefixedClaimOrExpression{Claim: "claim", Prefix: pointer.String("prefix")},
				Groups:   api.PrefixedClaimOrExpression{Claim: "claim", Prefix: pointer.String("prefix")},
			},
			want: "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := validateClaimMappings(compiler, tt.in, fldPath).ToAggregate()
			if d := cmp.Diff(tt.want, errString(got)); d != "" {
				t.Fatalf("ClaimMappings validation mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestValidateUserInfoValidationRules(t *testing.T) {
	fldPath := field.NewPath("issuer", "userValidationRules")

	testCases := []struct {
		name string
		in   []api.UserValidationRule
		want string
	}{
		{
			name: "user info validation rule, rule is empty",
			in:   []api.UserValidationRule{{}},
			want: "issuer.userValidationRules[0].rule: Required value: rule is required",
		},
		{
			name: "duplicate rule",
			in: []api.UserValidationRule{
				{Rule: "user.username == 'foo'"},
				{Rule: "user.username == 'foo'"},
			},
			want: `issuer.userValidationRules[1].rule: Duplicate value: "user.username == 'foo'"`,
		},
		{
			name: "valid user info validation rule",
			in: []api.UserValidationRule{
				{Rule: "user.username == 'foo'"},
				{Rule: "!user.username.startsWith('system:')", Message: "username cannot used reserved system: prefix"},
			},
			want: "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := validateUserValidationRules(compiler, tt.in, fldPath).ToAggregate()
			if d := cmp.Diff(tt.want, errString(got)); d != "" {
				t.Fatalf("UserValidationRules validation mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func errString(errs errors.Aggregate) string {
	if errs != nil {
		return errs.Error()
	}
	return ""
}

type (
	test struct {
		name            string
		configuration   api.AuthorizationConfiguration
		expectedErrList field.ErrorList
		knownTypes      sets.String
		repeatableTypes sets.String
	}
)

func TestValidateAuthorizationConfiguration(t *testing.T) {
	badKubeConfigFile := "../some/relative/path/kubeconfig"

	tempKubeConfigFile, err := os.CreateTemp("/tmp", "kubeconfig")
	if err != nil {
		t.Fatalf("failed to set up temp file: %v", err)
	}
	tempKubeConfigFilePath := tempKubeConfigFile.Name()
	defer os.Remove(tempKubeConfigFilePath)

	tests := []test{
		{
			name: "atleast one authorizer should be defined",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("authorizers"), "at least one authorization mode must be defined")},
			knownTypes:      sets.NewString(),
			repeatableTypes: sets.NewString(),
		},
		{
			name: "type and name are required if an authorizer is defined",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{},
				},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("type"), "")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "authorizer names should be of non-zero length",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Foo",
						Name: "",
					},
				},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("name"), "")},
			knownTypes:      sets.NewString(string("Foo")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "authorizer names should be unique",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Foo",
						Name: "foo",
					},
					{
						Type: "Bar",
						Name: "foo",
					},
				},
			},
			expectedErrList: field.ErrorList{field.Duplicate(field.NewPath("name"), "foo")},
			knownTypes:      sets.NewString(string("Foo"), string("Bar")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "authorizer names should be DNS1123 labels",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Foo",
						Name: "myauthorizer",
					},
				},
			},
			expectedErrList: field.ErrorList{},
			knownTypes:      sets.NewString(string("Foo")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "authorizer names should be DNS1123 subdomains",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Foo",
						Name: "foo.example.domain",
					},
				},
			},
			expectedErrList: field.ErrorList{},
			knownTypes:      sets.NewString(string("Foo")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "authorizer names should not be invalid DNS1123 labels or subdomains",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Foo",
						Name: "FOO.example.domain",
					},
				},
			},
			expectedErrList: field.ErrorList{field.Invalid(field.NewPath("name"), "FOO.example.domain", "")},
			knownTypes:      sets.NewString(string("Foo")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "bare minimum configuration with Webhook",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:                            "NoOpinion",
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "bare minimum configuration with multiple webhooks",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:                            "NoOpinion",
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
					{
						Type: "Webhook",
						Name: "second-webhook",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:                            "NoOpinion",
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "configuration with unknown types",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Foo",
					},
				},
			},
			expectedErrList: field.ErrorList{field.NotSupported(field.NewPath("type"), "Foo", []string{"..."})},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "configuration with not repeatable types",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Foo",
						Name: "foo-1",
					},
					{
						Type: "Foo",
						Name: "foo-2",
					},
				},
			},
			expectedErrList: field.ErrorList{field.Duplicate(field.NewPath("type"), "Foo")},
			knownTypes:      sets.NewString(string("Foo")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "when type=Webhook, webhook needs to be defined",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
					},
				},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("webhook"), "required when type=Webhook")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "when type!=Webhook, webhooks needs to be nil",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type:    "Foo",
						Name:    "foo",
						Webhook: &api.WebhookConfiguration{},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Invalid(field.NewPath("webhook"), "non-null", "may only be specified when type=Webhook")},
			knownTypes:      sets.NewString(string("Foo")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "timeout should be specified",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							FailurePolicy:                            "NoOpinion",
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("timeout"), "")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		//
		{
			name: "timeout shouldn't be zero",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							FailurePolicy:                            "NoOpinion",
							Timeout:                                  metav1.Duration{Duration: 0 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("timeout"), "")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "timeout shouldn't be negative",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							FailurePolicy:                            "NoOpinion",
							Timeout:                                  metav1.Duration{Duration: -30 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Invalid(field.NewPath("timeout"), time.Duration(-30*time.Second).String(), "must be > 0s and <= 30s")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "timeout shouldn't be greater than 30seconds",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							FailurePolicy:                            "NoOpinion",
							Timeout:                                  metav1.Duration{Duration: 60 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Invalid(field.NewPath("timeout"), time.Duration(60*time.Second).String(), "must be > 0s and <= 30s")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "authorizedTTL should be defined ",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							FailurePolicy:                            "NoOpinion",
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("authorizedTTL"), "")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "authorizedTTL shouldn't be negative",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							FailurePolicy:                            "NoOpinion",
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: -30 * time.Second},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Invalid(field.NewPath("authorizedTTL"), time.Duration(-30*time.Second).String(), "must be > 0s")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "unauthorizedTTL should be defined ",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							FailurePolicy:                            "NoOpinion",
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("unauthorizedTTL"), "")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "unauthorizedTTL shouldn't be negative",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							FailurePolicy:                            "NoOpinion",
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: -30 * time.Second},
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Invalid(field.NewPath("unauthorizedTTL"), time.Duration(-30*time.Second).String(), "must be > 0s")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "SAR should be defined",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							MatchConditionSubjectAccessReviewVersion: "v1",
							FailurePolicy:                            "NoOpinion",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("subjectAccessReviewVersion"), "")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "SAR should be one of v1 and v1beta1",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:                            "NoOpinion",
							SubjectAccessReviewVersion:               "v2beta1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.NotSupported(field.NewPath("subjectAccessReviewVersion"), "v2beta1", []string{"v1", "v1beta1"})},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "MatchConditionSAR should be defined",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                    metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:              metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:            metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:              "NoOpinion",
							SubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("matchConditionSubjectAccessReviewVersion"), "")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "MatchConditionSAR must not be anything other than v1",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:                            "NoOpinion",
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1beta1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.NotSupported(field.NewPath("matchConditionSubjectAccessReviewVersion"), "v1beta1", []string{"v1"})},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "failurePolicy should be defined",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("failurePolicy"), "")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "failurePolicy should be one of \"NoOpinion\" or \"Deny\"",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:                            "AlwaysAllow",
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "InClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.NotSupported(field.NewPath("failurePolicy"), "AlwaysAllow", []string{"NoOpinion", "Deny"})},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "connectionInfo should be defined",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:                            "NoOpinion",
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("connectionInfo"), "")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "connectionInfo should be one of InClusterConfig or KubeConfigFile",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:                            "NoOpinion",
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "ExternalClusterConfig",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{
				field.NotSupported(field.NewPath("connectionInfo"), api.WebhookConnectionInfo{Type: "ExternalClusterConfig"}, []string{"InClusterConfig", "KubeConfigFile"}),
			},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "if connectionInfo=InClusterConfig, then kubeConfigFile should be nil",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:                            "NoOpinion",
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type:           "InClusterConfig",
								KubeConfigFile: new(string),
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{
				field.Invalid(field.NewPath("connectionInfo", "kubeConfigFile"), "", "can only be set when type=KubeConfigFile"),
			},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "if connectionInfo=KubeConfigFile, then KubeConfigFile should be defined",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:                            "NoOpinion",
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type: "KubeConfigFile",
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Required(field.NewPath("kubeConfigFile"), "")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "if connectionInfo=KubeConfigFile, then KubeConfigFile should be defined, must be an absolute path, should exist, shouldn't be a symlink",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:                            "NoOpinion",
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type:           "KubeConfigFile",
								KubeConfigFile: &badKubeConfigFile,
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{field.Invalid(field.NewPath("kubeConfigFile"), badKubeConfigFile, "must be an absolute path")},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},
		{
			name: "if connectionInfo=KubeConfigFile, an existent file needs to be passed",
			configuration: api.AuthorizationConfiguration{
				Authorizers: []api.AuthorizerConfiguration{
					{
						Type: "Webhook",
						Name: "default",
						Webhook: &api.WebhookConfiguration{
							Timeout:                                  metav1.Duration{Duration: 5 * time.Second},
							AuthorizedTTL:                            metav1.Duration{Duration: 5 * time.Minute},
							UnauthorizedTTL:                          metav1.Duration{Duration: 30 * time.Second},
							FailurePolicy:                            "NoOpinion",
							SubjectAccessReviewVersion:               "v1",
							MatchConditionSubjectAccessReviewVersion: "v1",
							ConnectionInfo: api.WebhookConnectionInfo{
								Type:           "KubeConfigFile",
								KubeConfigFile: &tempKubeConfigFilePath,
							},
						},
					},
				},
			},
			expectedErrList: field.ErrorList{},
			knownTypes:      sets.NewString(string("Webhook")),
			repeatableTypes: sets.NewString(string("Webhook")),
		},

		// TODO: When the CEL expression validator is implemented, add a few test cases to typecheck the expression
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			errList := ValidateAuthorizationConfiguration(nil, &test.configuration, test.knownTypes, test.repeatableTypes)
			if len(errList) != len(test.expectedErrList) {
				t.Errorf("expected %d errs, got %d, errors %v", len(test.expectedErrList), len(errList), errList)
			}

			for i, expected := range test.expectedErrList {
				if expected.Type.String() != errList[i].Type.String() {
					t.Errorf("expected err type %s, got %s",
						expected.Type.String(),
						errList[i].Type.String())
				}
				if expected.BadValue != errList[i].BadValue {
					t.Errorf("expected bad value '%s', got '%s'",
						expected.BadValue,
						errList[i].BadValue)
				}
			}
		})

	}
}
