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
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	api "k8s.io/apiserver/pkg/authentication/config"
	"k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
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
	} else if len(authenticator.Issuer.ClientIDs) > 1 {
		// This restriction is only for the parity with the current implementation using --oidc-client-id flag.
		// We will relax this restriction in the follow up as we add support for multiple clientIDs.
		allErrs = append(allErrs, field.Forbidden(fldPath.Child("issuer", "clientIDs"), "only one clientID is allowed"))
	}

	if authenticator.ClaimValidationRules != nil {
		allErrs = append(allErrs, validateClaimValidationRules(authenticator.ClaimValidationRules, validationOptions{}, fldPath.Child("claimValidationRules"))...)
	}

	return allErrs
}

func validateClaimValidationRules(rules []api.ClaimValidationRule, opts validationOptions, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	for i, rule := range rules {
		fldPath := fldPath.Index(i)

		if rule.Claim == "" && rule.Expression == "" {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("expression"), "claim and expression can't be specified at the same time"))
			continue
		}
		if rule.Expression != "" {
			allErrs = append(allErrs, validateClaimValidationRuleExpression(rule.Expression, opts, fldPath)...)
		}
	}

	return allErrs
}

func validateCELCondition(expression authenticationcel.ExpressionAccessor, envType environment.Type, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	result := compiler.CompileCELExpression(expression, envType)
	if result.Error != nil {
		switch result.Error.Type {
		case cel.ErrorTypeRequired:
			allErrors = append(allErrors, field.Required(fldPath, result.Error.Detail))
		case cel.ErrorTypeInvalid:
			allErrors = append(allErrors, field.Invalid(fldPath, expression.GetExpression(), result.Error.Detail))
		case cel.ErrorTypeInternal:
			allErrors = append(allErrors, field.InternalError(fldPath, result.Error))
		default:
			allErrors = append(allErrors, field.InternalError(fldPath, fmt.Errorf("unsupported error type: %w", result.Error)))
		}
	}
	return allErrors
}

type validationOptions struct {
	preexistingExpressions preexistingExpressions
}

type preexistingExpressions struct {
	claimValidationRuleExpressions sets.Set[string]
}

func newPreexistingExpressions() preexistingExpressions {
	return preexistingExpressions{
		claimValidationRuleExpressions: sets.New[string](),
	}
}

func validateClaimValidationRuleExpression(expression string, opts validationOptions, fldPath *field.Path) field.ErrorList {
	envType := environment.NewExpressions
	if opts.preexistingExpressions.claimValidationRuleExpressions.Has(expression) {
		envType = environment.StoredExpressions
	}

	return validateCELCondition(&oidc.ClaimValidationCondition{
		Expression: expression,
	}, envType, fldPath)
}

var compiler = authenticationcel.NewCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))
