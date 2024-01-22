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
	"fmt"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// mapper implements the ClaimsMapper and UserMapper interface.
type mapper struct {
	compilationResults []CompilationResult
}

// CELMapper is a struct that holds the compiled expressions for
// username, groups, uid, extra, claimValidation and userValidation
type CELMapper struct {
	Username             StringMapper
	Groups               StringArrayMapper
	UID                  StringMapper
	Extra                MapStringStringArrayMapper
	ClaimValidationRules BoolMapper
	UserValidationRules  BoolMapper
}

// NewClaimsMapper returns a new ClaimsMapper.
func NewClaimsMapper(compilationResults []CompilationResult) ClaimsMapper {
	return &mapper{
		compilationResults: compilationResults,
	}
}

// NewUserMapper returns a new UserMapper.
func NewUserMapper(compilationResults []CompilationResult) UserMapper {
	return &mapper{
		compilationResults: compilationResults,
	}
}

// EvalClaimMapping evaluates the given claim mapping expression and returns a EvaluationResult.
func (m *mapper) EvalClaimMapping(ctx context.Context, claims *unstructured.Unstructured) (EvaluationResult, error) {
	results, err := m.eval(ctx, map[string]interface{}{claimsVarName: claims.Object})
	if err != nil {
		return EvaluationResult{}, err
	}
	if len(results) != 1 {
		return EvaluationResult{}, fmt.Errorf("expected 1 evaluation result, got %d", len(results))
	}
	return results[0], nil
}

// EvalClaimMappings evaluates the given expressions and returns a list of EvaluationResult.
func (m *mapper) EvalClaimMappings(ctx context.Context, claims *unstructured.Unstructured) ([]EvaluationResult, error) {
	return m.eval(ctx, map[string]interface{}{claimsVarName: claims.Object})
}

// EvalUser evaluates the given user expressions and returns a list of EvaluationResult.
func (m *mapper) EvalUser(ctx context.Context, userInfo *unstructured.Unstructured) ([]EvaluationResult, error) {
	return m.eval(ctx, map[string]interface{}{userVarName: userInfo.Object})
}

func (m *mapper) eval(ctx context.Context, input map[string]interface{}) ([]EvaluationResult, error) {
	evaluations := make([]EvaluationResult, len(m.compilationResults))

	for i, compilationResult := range m.compilationResults {
		var evaluation = &evaluations[i]
		evaluation.ExpressionAccessor = compilationResult.ExpressionAccessor

		evalResult, _, err := compilationResult.Program.ContextEval(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("expression '%s' resulted in error: %w", compilationResult.ExpressionAccessor.GetExpression(), err)
		}

		evaluation.EvalResult = evalResult
	}

	return evaluations, nil
}

func eval(ctx context.Context, input map[string]interface{}, compilationResults ...CompilationResult) ([]EvaluationResult, error) {
	evaluations := make([]EvaluationResult, len(compilationResults))

	for i, compilationResult := range compilationResults {
		var evaluation = &evaluations[i]
		evaluation.ExpressionAccessor = compilationResult.ExpressionAccessor

		evalResult, _, err := compilationResult.Program.ContextEval(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("expression '%s' resulted in error: %w", compilationResult.ExpressionAccessor.GetExpression(), err)
		}

		evaluation.EvalResult = evalResult
	}

	return evaluations, nil
}

type BoolMapper interface {
	EvalBool(ctx context.Context, claims *unstructured.Unstructured) (bool, error)
}

type StringMapper interface {
	EvalString(ctx context.Context, claims *unstructured.Unstructured) (string, error)
}

type StringArrayMapper interface {
	EvalStringArray(ctx context.Context, claims *unstructured.Unstructured) ([]string, error)
}

type MapStringStringArrayMapper interface {
	EvalMapStringStringArray(ctx context.Context, claims *unstructured.Unstructured) (map[string][]string, error)
}

type usernameMapper struct {
	compilationResult CompilationResult
}

func (m *usernameMapper) EvalString(ctx context.Context, claims *unstructured.Unstructured) (string, error) {
	evaluations, err := eval(ctx, claims.Object, m.compilationResult)
	if err != nil {
		return "", err
	}
	if len(evaluations) != 1 {
		return "", fmt.Errorf("expected 1 evaluation result, got %d", len(evaluations))
	}
	if evaluations[0].EvalResult.Type() != celgo.StringType {
		return "", fmt.Errorf("expected string return type, got %s", evaluations[0].EvalResult.Type())
	}
	return evaluations[0].EvalResult.Value().(string), nil
}

type groupsMapper struct {
	compilationResult CompilationResult
}

func (m *groupsMapper) EvalStringArray(ctx context.Context, claims *unstructured.Unstructured) ([]string, error) {
	evaluations, err := eval(ctx, claims.Object, m.compilationResult)
	if err != nil {
		return nil, err
	}
	if len(evaluations) != 1 {
		return nil, fmt.Errorf("expected 1 evaluation result, got %d", len(evaluations))
	}

	return convertCELValueToStringList(evaluations[0].EvalResult)
}

type uidMapper struct {
	compilationResult CompilationResult
}

func (m *uidMapper) EvalString(ctx context.Context, claims *unstructured.Unstructured) (string, error) {
	evaluations, err := eval(ctx, claims.Object, m.compilationResult)
	if err != nil {
		return "", err
	}
	if len(evaluations) != 1 {
		return "", fmt.Errorf("expected 1 evaluation result, got %d", len(evaluations))
	}
	if evaluations[0].EvalResult.Type() != celgo.StringType {
		return "", fmt.Errorf("expected string return type, got %s", evaluations[0].EvalResult.Type())
	}
	return evaluations[0].EvalResult.Value().(string), nil
}

type extraMapper struct {
	compilationResult CompilationResult
}

func (m *extraMapper) EvalMapStringStringArray(ctx context.Context, claims *unstructured.Unstructured) (map[string][]string, error) {
	evaluations, err := eval(ctx, claims.Object, m.compilationResult)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string, len(evaluations))
	for _, evaluation := range evaluations {
		extraMapping, ok := result.ExpressionAccessor.(*authenticationcel.ExtraMappingExpression)
		if !ok {
			return nil, fmt.Errorf("oidc: error evaluating extra claim expression: %w", fmt.Errorf("invalid type conversion, expected ExtraMappingCondition"))
		}

		extraValues, err := convertCELValueToStringList(result.EvalResult)
		if err != nil {
			return nil, fmt.Errorf("oidc: error evaluating extra claim expression: %s: %w", extraMapping.Expression, err)
		}

		if len(extraValues) == 0 {
			continue
		}

		extra[extraMapping.Key] = extraValues
	}
}

// convertCELValueToStringList converts the CEL value to a string list.
// The CEL value needs to be either a string or a list of strings.
// "", [] are treated as not being present and will return nil.
// Empty string in a list of strings is treated as not being present and will be filtered out.
func convertCELValueToStringList(val ref.Val) ([]string, error) {
	switch val.Type().TypeName() {
	case celgo.StringType.TypeName():
		out := val.Value().(string)
		if len(out) == 0 {
			return nil, nil
		}
		return []string{out}, nil

	case celgo.ListType(nil).TypeName():
		var result []string
		switch val.Value().(type) {
		case []interface{}:
			for _, v := range val.Value().([]interface{}) {
				out, ok := v.(string)
				if !ok {
					return nil, fmt.Errorf("expression must return a string or a list of strings")
				}
				if len(out) == 0 {
					continue
				}
				result = append(result, out)
			}
		case []ref.Val:
			for _, v := range val.Value().([]ref.Val) {
				out, ok := v.Value().(string)
				if !ok {
					return nil, fmt.Errorf("expression must return a string or a list of strings")
				}
				if len(out) == 0 {
					continue
				}
				result = append(result, out)
			}
		default:
			return nil, fmt.Errorf("expression must return a string or a list of strings")
		}

		if len(result) == 0 {
			return nil, nil
		}

		return result, nil
	case celgo.NullType.TypeName():
		return nil, nil
	default:
		return nil, fmt.Errorf("expression must return a string or a list of strings")
	}
}
