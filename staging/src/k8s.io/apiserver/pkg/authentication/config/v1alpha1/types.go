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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AuthenticationConfiguration struct {
	metav1.TypeMeta

	// jwt is a list of OIDC providers to authenticate Kubernetes users.
	// For an incoming token, each JWT authenticator will be attempted in
	// the order in which it is specified in this list.  Note however that
	// other authenticators may run before or after the JWT authenticators.
	// The specific position of JWT authenticators in relation to other
	// authenticators is neither defined nor stable across releases.  Since
	// each JWT authenticator must have a unique issuer URL, at most one
	// JWT authenticator will attempt to cryptographically validate the token.
	JWT []JWTAuthenticator `json:"jwt"`
}

type JWTAuthenticator struct {
	// issuer is a basic OIDC provider connection options.
	Issuer Issuer `json:"issuer"`

	// claimValidationRules are rules that are applied to validate token claims to authenticate users.
	// +optional
	ClaimValidationRules []ClaimValidationRule `json:"claimValidationRules,omitempty"`

	// claimMappings points claims of a token to be treated as user attributes.
	ClaimMappings ClaimMappings `json:"claimMappings"`
}

type Issuer struct {
	// url points to the issuer URL in a format https://url/path.
	// This must match the "iss" claim in the presented JWT, and the issuer returned from discovery.
	// Same value as the --oidc-issuer-url flag.
	// Used to fetch discovery information unless overridden by discoveryURL.
	// Required to be unique.
	// Note that egress selection configuration is not used for this network connection.
	// TODO(aramase): decide if we want to support egress selection configuration and how to do so.
	URL string `json:"url"`

	// certificateAuthority contains PEM-encoded certificate authority certificates
	// used to validate the connection when fetching discovery information.
	// If unset, the system verifier is used.
	// Same value as the content of the file referenced by the --oidc-ca-file flag.
	// +optional
	CertificateAuthority []byte `json:"certificateAuthority,omitempty"`

	// clientIDs is the set of acceptable audiences the JWT must be issued to.
	// At least one of the entries must match the "aud" claim in presented JWTs.
	// Same value as the --oidc-client-id flag (though this field supports an array).
	// Required to be non-empty.
	ClientIDs []string `json:"clientIDs"`
}

type ClaimValidationRule struct {
	// claim is the name of a required claim.
	// Same as --oidc-required-claim flag.
	// Only string claims are supported.
	// +optional
	Claim string `json:"claim"`
	// requiredValue is the value of a required claim.
	// Same as --oidc-required-claim flag.
	// +optional
	RequiredValue string `json:"requiredValue"`

	// expression is a logical expression that is written in CEL https://github.com/google/cel-go.
	// Must return true for the validation to pass.
	// Mutually exclusive with claim and requiredValue.
	// +optional
	Expression string `json:"expression"`
	// message customizes the returned error message when expression returns false.
	// Mutually exclusive with claim and requiredValue.
	// Note that messageExpression is explicitly not supported to avoid
	// misconfigured expressions from leaking JWT payload contents.
	// +optional
	Message string `json:"message,omitempty"`
}

type ClaimMappings struct {
	// username represents an option for the username attribute.
	// Claim must be a singular string claim.
	// Possible prefixes based on the config:
	//     (1) if userName.prefix = "-", no prefix will be added to the username
	//     (2) if userName.prefix = "" and userName.claim != "email", prefix will be "<issuer.url>#"
	//     (3) if userName.expression is set instead, result of expression is used as-is without any implicit prefix
	// (1) and (2) ensure backward compatibility with the --oidc-username-claim and --oidc-username-prefix flags
	Username PrefixedClaimOrExpression `json:"username"`
	// groups represents an option for the groups attribute.
	// Claim must be a string or string array claim.
	// +optional
	Groups PrefixedClaimOrExpression `json:"groups,omitempty"`
}

type PrefixedClaimOrExpression struct {
	// claim is the JWT claim to use.
	// +optional
	Claim string `json:"claim"`
	// prefix is prepended to claim to prevent clashes with existing names.
	// +optional
	Prefix string `json:"prefix"`
}
