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

package cel

import (
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/cel/environment"
)

func TestCompileCELExpression(t *testing.T) {
	testCases := []struct {
		name                string
		expressionAccessors []ExpressionAccessor
		envVarName          string
	}{
		{
			name: "valid ClaimMappingCondition",
			expressionAccessors: []ExpressionAccessor{
				&ClaimMappingCondition{
					Expression: "claims.foo",
				},
			},
			envVarName: ClaimsVarName,
		},
		{
			name: "valid ClaimValidationCondition",
			expressionAccessors: []ExpressionAccessor{
				&ClaimValidationCondition{
					Expression: "claims.foo == 'bar'",
				},
			},
			envVarName: ClaimsVarName,
		},
		{
			name: "valid ExtraMapppingCondition",
			expressionAccessors: []ExpressionAccessor{
				&ExtraMappingCondition{
					Expression: "claims.foo",
				},
			},
			envVarName: ClaimsVarName,
		},
		{
			name: "valid UserValidationCondition",
			expressionAccessors: []ExpressionAccessor{
				&UserValidationCondition{
					Expression: "user.username == 'foo'",
				},
			},
			envVarName: UserVarName,
		},
	}

	compiler := NewCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, expressionAccessor := range tc.expressionAccessors {
				_, err := compiler.CompileCELExpression(expressionAccessor, tc.envVarName)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCompileCELExpressionError(t *testing.T) {
	testCases := []struct {
		name                string
		expressionAccessors []ExpressionAccessor
		envVarName          string
		wantErr             string
	}{
		{
			name: "invalid ClaimValidationCondition",
			expressionAccessors: []ExpressionAccessor{
				&ClaimValidationCondition{
					Expression: "claims.foo",
				},
			},
			envVarName: ClaimsVarName,
			wantErr:    "must evaluate to bool",
		},
		{
			name: "invalid UserValidationCondition",
			expressionAccessors: []ExpressionAccessor{
				&UserValidationCondition{
					Expression: "user.username",
				},
			},
			envVarName: UserVarName,
			wantErr:    "must evaluate to bool",
		},
		{
			name: "ClamMappingCondition with wrong env",
			expressionAccessors: []ExpressionAccessor{
				&ClaimMappingCondition{
					Expression: "claims.foo",
				},
			},
			envVarName: UserVarName,
			wantErr:    `compilation failed: ERROR: <input>:1:1: undeclared reference to 'claims' (in container '')`,
		},
		{
			name: "ExtraMappingCondition with wrong env",
			expressionAccessors: []ExpressionAccessor{
				&ExtraMappingCondition{
					Expression: "claims.foo",
				},
			},
			envVarName: UserVarName,
			wantErr:    `compilation failed: ERROR: <input>:1:1: undeclared reference to 'claims' (in container '')`,
		},
		{
			name: "ClaimValidationCondition with wrong env",
			expressionAccessors: []ExpressionAccessor{
				&ClaimValidationCondition{
					Expression: "claims.foo == 'bar'",
				},
			},
			envVarName: UserVarName,
		},
		{
			name: "UserValidationCondition with wrong env",
			expressionAccessors: []ExpressionAccessor{
				&UserValidationCondition{
					Expression: "user.username == 'foo'",
				},
			},
			envVarName: ClaimsVarName,
		},
		{
			name: "UserValidationCondition expression with unknown field",
			expressionAccessors: []ExpressionAccessor{
				&UserValidationCondition{
					Expression: "user.unknown == 'foo'",
				},
			},
			envVarName: UserVarName,
			wantErr:    `compilation failed: ERROR: <input>:1:5: undefined field 'unknown'`,
		},
		{
			name: "invalid ClaimMappingCondition",
			expressionAccessors: []ExpressionAccessor{
				&ClaimMappingCondition{
					Expression: "claims + 1",
				},
			},
			envVarName: ClaimsVarName,
			wantErr:    `compilation failed: ERROR: <input>:1:8: found no matching overload for '_+_' applied to '(map(string, any), int)'`,
		},
	}

	compiler := NewCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, expressionAccessor := range tc.expressionAccessors {
				_, err := compiler.CompileCELExpression(expressionAccessor, tc.envVarName)
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("expected error to contain %q but got %q", tc.wantErr, err.Error())
				}
			}
		})
	}
}
