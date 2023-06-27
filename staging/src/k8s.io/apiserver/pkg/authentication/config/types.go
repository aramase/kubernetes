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

package config

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AuthenticationConfiguration struct {
	metav1.TypeMeta

	JWT []JWTAuthenticator
}

type JWTAuthenticator struct {
	Issuer               Issuer
	ClaimValidationRules []ClaimValidationRule
	ClaimMappings        ClaimMappings
}

type Issuer struct {
	URL                  string
	CertificateAuthority []byte
	ClientIDs            []string
}

type ClaimValidationRule struct {
	Claim         string
	RequiredValue string
}

type ClaimMappings struct {
	Username PrefixedClaimOrExpression
	Groups   PrefixedClaimOrExpression
}

type PrefixedClaimOrExpression struct {
	Claim  string
	Prefix string
}
