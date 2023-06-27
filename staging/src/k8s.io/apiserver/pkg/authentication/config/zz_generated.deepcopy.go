//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

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

// Code generated by deepcopy-gen. DO NOT EDIT.

package config

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AuthenticationConfiguration) DeepCopyInto(out *AuthenticationConfiguration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.JWT != nil {
		in, out := &in.JWT, &out.JWT
		*out = make([]JWTAuthenticator, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AuthenticationConfiguration.
func (in *AuthenticationConfiguration) DeepCopy() *AuthenticationConfiguration {
	if in == nil {
		return nil
	}
	out := new(AuthenticationConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AuthenticationConfiguration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClaimMappings) DeepCopyInto(out *ClaimMappings) {
	*out = *in
	out.Username = in.Username
	out.Groups = in.Groups
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClaimMappings.
func (in *ClaimMappings) DeepCopy() *ClaimMappings {
	if in == nil {
		return nil
	}
	out := new(ClaimMappings)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClaimValidationRule) DeepCopyInto(out *ClaimValidationRule) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClaimValidationRule.
func (in *ClaimValidationRule) DeepCopy() *ClaimValidationRule {
	if in == nil {
		return nil
	}
	out := new(ClaimValidationRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Issuer) DeepCopyInto(out *Issuer) {
	*out = *in
	if in.CertificateAuthority != nil {
		in, out := &in.CertificateAuthority, &out.CertificateAuthority
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
	if in.ClientIDs != nil {
		in, out := &in.ClientIDs, &out.ClientIDs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Issuer.
func (in *Issuer) DeepCopy() *Issuer {
	if in == nil {
		return nil
	}
	out := new(Issuer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *JWTAuthenticator) DeepCopyInto(out *JWTAuthenticator) {
	*out = *in
	in.Issuer.DeepCopyInto(&out.Issuer)
	if in.ClaimValidationRules != nil {
		in, out := &in.ClaimValidationRules, &out.ClaimValidationRules
		*out = make([]ClaimValidationRule, len(*in))
		copy(*out, *in)
	}
	out.ClaimMappings = in.ClaimMappings
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new JWTAuthenticator.
func (in *JWTAuthenticator) DeepCopy() *JWTAuthenticator {
	if in == nil {
		return nil
	}
	out := new(JWTAuthenticator)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PrefixedClaimOrExpression) DeepCopyInto(out *PrefixedClaimOrExpression) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PrefixedClaimOrExpression.
func (in *PrefixedClaimOrExpression) DeepCopy() *PrefixedClaimOrExpression {
	if in == nil {
		return nil
	}
	out := new(PrefixedClaimOrExpression)
	in.DeepCopyInto(out)
	return out
}
