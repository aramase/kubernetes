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
	"net/url"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	api "k8s.io/apiserver/pkg/authentication/config"
)

const (
	authenticationConfigNilErr = "AuthenticationConfiguration can't be nil"
	atLeastOneRequiredErrFmt   = "at least one %s is required"
	issuerURLSchemeErr         = "issuer URL scheme must be https"
	issuerURLRequiredErr       = "issuer URL is required"
)

var (
	root = field.NewPath("jwt")
)

// ValidateAuthenticationConfiguration validates a given AuthenticationConfiguration.
func ValidateAuthenticationConfiguration(c *api.AuthenticationConfiguration) field.ErrorList {
	allErrs := field.ErrorList{}

	if c == nil {
		allErrs = append(allErrs, field.Required(field.NewPath(""), authenticationConfigNilErr))
		return allErrs
	}

	if len(c.JWT) == 0 {
		allErrs = append(allErrs, field.Required(root, fmt.Sprintf(atLeastOneRequiredErrFmt, root)))
		return allErrs
	}

	seenIssuers := sets.NewString()
	for i, a := range c.JWT {
		fldPath := root.Index(i)

		if seenIssuers.Has(a.Issuer.URL) {
			allErrs = append(allErrs, field.Duplicate(fldPath.Child("issuer", "url"), a.Issuer.URL))
			continue
		}
		seenIssuers.Insert(a.Issuer.URL)

		allErrs = append(allErrs, validateJWTAuthenticator(a, fldPath)...)
	}

	return allErrs
}

func validateJWTAuthenticator(authenticator api.JWTAuthenticator, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if authenticator.Issuer.URL == "" {
		allErrs = append(allErrs, field.Required(fldPath.Child("issuer", "url"), issuerURLRequiredErr))
	} else {
		u, err := url.Parse(authenticator.Issuer.URL)
		if err != nil {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("issuer", "url"), authenticator.Issuer.URL, err.Error()))
		} else if u.Scheme != "https" {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("issuer", "url"), authenticator.Issuer.URL, issuerURLSchemeErr))
		}
	}

	if len(authenticator.Issuer.ClientIDs) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("issuer", "clientIDs"), fmt.Sprintf(atLeastOneRequiredErrFmt, fldPath.Child("issuer", "clientIDs"))))
	}

	return allErrs
}
