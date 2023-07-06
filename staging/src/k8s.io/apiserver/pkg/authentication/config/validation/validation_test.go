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
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/util/validation/field"
	api "k8s.io/apiserver/pkg/authentication/config"
)

func TestValidateAuthenticationConfiguration(t *testing.T) {
	testCases := []struct {
		name string
		in   *api.AuthenticationConfiguration
		want field.ErrorList
	}{
		{
			name: "authentication configuration is nil",
			in:   nil,
			want: field.ErrorList{
				field.Required(field.NewPath(""), authenticationConfigNilErr),
			},
		},
		{
			name: "jwt authenticator is empty",
			in:   &api.AuthenticationConfiguration{},
			want: field.ErrorList{
				field.Required(root, fmt.Sprintf(atLeastOneRequiredErrFmt, root)),
			},
		},
		{
			name: "duplicate issuer url",
			in: &api.AuthenticationConfiguration{
				JWT: []api.JWTAuthenticator{
					{
						Issuer: api.Issuer{
							URL:       "https://issuer-url",
							ClientIDs: []string{"client-id"},
						},
					},
					{
						Issuer: api.Issuer{
							URL:       "https://issuer-url",
							ClientIDs: []string{"another-client-id"},
						},
					},
				},
			},
			want: field.ErrorList{
				field.Duplicate(root.Index(1).Child("issuer", "url"), "https://issuer-url"),
			},
		},
		{
			name: "valid authentication configuration",
			in: &api.AuthenticationConfiguration{
				JWT: []api.JWTAuthenticator{
					{
						Issuer: api.Issuer{
							URL:       "https://issuer-url",
							ClientIDs: []string{"client-id"},
						},
					},
				},
			},
			want: field.ErrorList{},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateAuthenticationConfiguration(tt.in)
			if d := cmp.Diff(tt.want, got); d != "" {
				t.Fatalf("AuthenticationConfiguration validation mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestValidateJWTAuthenticator(t *testing.T) {
	jwtField := field.NewPath("jwt")

	testCases := []struct {
		name string
		in   api.JWTAuthenticator
		want field.ErrorList
	}{
		{
			name: "issuer url is empty",
			in: api.JWTAuthenticator{
				Issuer: api.Issuer{
					ClientIDs: []string{"client-id"},
				},
			},
			want: field.ErrorList{
				field.Required(jwtField.Child("issuer", "url"), issuerURLRequiredErr),
			},
		},
		{
			name: "issuer url is not https",
			in: api.JWTAuthenticator{
				Issuer: api.Issuer{
					URL:       "http://issuer-url",
					ClientIDs: []string{"client-id"},
				},
			},
			want: field.ErrorList{
				field.Invalid(jwtField.Child("issuer", "url"), "http://issuer-url", issuerURLSchemeErr),
			},
		},
		{
			name: "client id is empty",
			in: api.JWTAuthenticator{
				Issuer: api.Issuer{
					URL: "https://issuer-url",
				},
			},
			want: field.ErrorList{
				field.Required(jwtField.Child("issuer", "clientIDs"), fmt.Sprintf(atLeastOneRequiredErrFmt, jwtField.Child("issuer", "clientIDs"))),
			},
		},
		{
			name: "more than one client id",
			in: api.JWTAuthenticator{
				Issuer: api.Issuer{
					URL:       "https://issuer-url",
					ClientIDs: []string{"client-id", "another-client-id"},
				},
			},
			want: field.ErrorList{
				field.Forbidden(jwtField.Child("issuer", "clientIDs"), "only one clientID is allowed"),
			},
		},
		{
			name: "valid jwt authenticator",
			in: api.JWTAuthenticator{
				Issuer: api.Issuer{
					URL:       "https://issuer-url",
					ClientIDs: []string{"client-id"},
				},
			},
			want: field.ErrorList{},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := validateJWTAuthenticator(tt.in, jwtField)
			if d := cmp.Diff(tt.want, got); d != "" {
				t.Fatalf("JWTAuthenticator validation mismatch (-want +got):\n%s", d)
			}
		})
	}
}
