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
	"context"
	"encoding/json"
	"strings"
	"testing"

	celgo "github.com/google/cel-go/cel"
	celtypes "github.com/google/cel-go/common/types"
	"github.com/stretchr/testify/require"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

type condition struct {
	Expression string
}

func (c *condition) GetExpression() string {
	return c.Expression
}

func (v *condition) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.BoolType}
}

func TestCompile(t *testing.T) {
	cases := []struct {
		name             string
		validation       []ExpressionAccessor
		errorExpressions map[string]string
	}{
		{
			name: "invalid syntax",
			validation: []ExpressionAccessor{
				&condition{
					Expression: "1 < 'asdf'",
				},
				&condition{
					Expression: "1 < 2",
				},
			},
			errorExpressions: map[string]string{
				"1 < 'asdf'": "found no matching overload for '_<_' applied to '(int, string)",
			},
		},
		{
			name: "valid syntax",
			validation: []ExpressionAccessor{
				&condition{
					Expression: "1 < 2",
				},
				&condition{
					Expression: "claims.hd == 'example.com' && claims.exp - claims.nbf <= 86400",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := filterCompiler{compiler: NewCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))}
			e := c.Compile(tc.validation, environment.NewExpressions)
			if e == nil {
				t.Fatalf("unexpected nil validator")
			}
			validations := tc.validation
			CompilationResults := e.(*filter).compilationResults
			require.Equal(t, len(validations), len(CompilationResults))

			meets := make([]bool, len(validations))
			for expr, expectErr := range tc.errorExpressions {
				for i, result := range CompilationResults {
					if validations[i].GetExpression() == expr {
						if result.Error == nil {
							t.Errorf("Expect expression '%s' to contain error '%v' but got no error", expr, expectErr)
						} else if !strings.Contains(result.Error.Error(), expectErr) {
							t.Errorf("Expected validations '%s' error to contain '%v' but got: %v", expr, expectErr, result.Error)
						}
						meets[i] = true
					}
				}
			}
			for i, meet := range meets {
				if !meet && CompilationResults[i].Error != nil {
					t.Errorf("Unexpected err '%v' for expression '%s'", CompilationResults[i].Error, validations[i].GetExpression())
				}
			}
		})
	}
}

func TestFilter(t *testing.T) {
	c := `{
		"iss": "https://example.com",
		"sub": "001",
		"aud": [
		  "cluster-a"
		],
		"exp": 1684274031,
		"iat": 1684270431,
		"nbf": 1684270431
	  }`

	var claims map[string]interface{}
	err := json.Unmarshal([]byte(c), &claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		name        string
		claims      map[string]interface{}
		validations []ExpressionAccessor
		results     []EvaluationResult
	}{
		{
			name:   "valid syntax",
			claims: claims,
			validations: []ExpressionAccessor{
				&condition{
					Expression: "claims.iss == 'https://example.com'",
				},
			},
			results: []EvaluationResult{
				{
					EvalResult: celtypes.True,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()).Extend(
				environment.VersionedOptions{
					IntroducedVersion: environment.DefaultCompatibilityVersion(),
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			c := NewFilterCompiler(env)
			f := c.Compile(tc.validations, environment.NewExpressions)
			if f == nil {
				t.Fatalf("unexpected nil validator")
			}
			validations := tc.validations
			CompilationResults := f.(*filter).compilationResults
			require.Equal(t, len(validations), len(CompilationResults))

			ctx := context.TODO()
			evalResults, _, err := f.ForInput(ctx, tc.claims, celconfig.RuntimeCELCostBudget)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			require.Equal(t, len(evalResults), len(tc.results))
			for i, result := range tc.results {
				if result.EvalResult != evalResults[i].EvalResult {
					t.Errorf("Expected result '%v' but got '%v'", result.EvalResult, evalResults[i].EvalResult)
				}
				if result.Error != nil && !strings.Contains(evalResults[i].Error.Error(), result.Error.Error()) {
					t.Errorf("Expected result '%v' but got '%v'", result.Error, evalResults[i].Error)
				}
			}
		})
	}
}
