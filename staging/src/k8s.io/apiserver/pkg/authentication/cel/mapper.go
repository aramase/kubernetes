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
	"reflect"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// mapper implements the Mapper interface.
type mapper struct {
	compilationResults []CompilationResult
}

// CELMapper is a struct that holds the compiled expressions for
// username, groups, uid, extra, claimValidation and userValidation
type CELMapper struct {
	Username             Mapper
	Groups               Mapper
	UID                  Mapper
	Extra                Mapper
	ClaimValidationRules Mapper
	UserValidationRules  Mapper
}

func NewMapper(compilationResults []CompilationResult) Mapper {
	return &mapper{
		compilationResults: compilationResults,
	}
}

func (m *mapper) Eval(ctx context.Context, claims, userInfo interface{}) ([]EvaluationResult, error) {
	evaluations := make([]EvaluationResult, len(m.compilationResults))

	userInfoVal, err := convertObjectToUnstructured(userInfo)
	if err != nil {
		return nil, fmt.Errorf("error converting user info to unstructured: %w", err)
	}

	claimsVal, err := convertObjectToUnstructured(&claims)
	if err != nil {
		return nil, fmt.Errorf("error converting claims to unstructured: %w", err)
	}

	va := map[string]interface{}{
		ClaimsVarName: claimsVal.Object,
		UserVarName:   userInfoVal.Object,
	}

	for i, compilationResult := range m.compilationResults {
		var evaluation = &evaluations[i]
		evaluation.ExpressionAccessor = compilationResult.ExpressionAccessor

		evalResult, _, err := compilationResult.Program.ContextEval(ctx, va)
		if err != nil {
			return nil, fmt.Errorf("expression '%s' resulted in error: %w", compilationResult.ExpressionAccessor.GetExpression(), err)
		}

		evaluation.EvalResult = evalResult
	}

	return evaluations, nil
}

func convertObjectToUnstructured(obj interface{}) (*unstructured.Unstructured, error) {
	if obj == nil || reflect.ValueOf(obj).IsNil() {
		return &unstructured.Unstructured{Object: nil}, nil
	}
	ret, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: ret}, nil
}
