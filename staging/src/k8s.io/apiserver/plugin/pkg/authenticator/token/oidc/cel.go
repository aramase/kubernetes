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

package oidc

import (
	"context"
	"fmt"
	"reflect"

	"github.com/google/cel-go/interpreter"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/pkg/cel"
	celenvironment "k8s.io/apiserver/pkg/cel/environment"
)

type evaluationActivation struct {
	claims, userInfo interface{}
}

// ResolveName implements the Activation interface.
func (a *evaluationActivation) ResolveName(name string) (interface{}, bool) {
	switch name {
	case authenticationcel.ClaimsVarName:
		return a.claims, true
	case authenticationcel.UserVarName:
		return a.userInfo, true
	default:
		return nil, false
	}
}

// Parent returns the parent of the current activation, may be nil.
// If non-nil, the parent will be searched during resolve calls.
func (a *evaluationActivation) Parent() interpreter.Activation {
	return nil
}

func compile(compiler authenticationcel.Compiler, expressionAccessors []authenticationcel.ExpressionAccessor, mode celenvironment.Type) *celMapper {
	compilationResults := make([]authenticationcel.CompilationResult, len(expressionAccessors))
	for i, expressionAccessor := range expressionAccessors {
		if expressionAccessor == nil {
			continue
		}
		compilationResults[i] = compiler.CompileCELExpression(expressionAccessor, mode)
	}

	return &celMapper{
		compilationResults: compilationResults,
	}
}

type celMapper struct {
	compilationResults []authenticationcel.CompilationResult
}

func (m *celMapper) eval(ctx context.Context, c claims, userInfo *authenticationv1.UserInfo) ([]authenticationcel.EvaluationResult, error) {
	evaluations := make([]authenticationcel.EvaluationResult, len(m.compilationResults))

	userInfoVal, err := convertObjectToUnstructured(userInfo)
	if err != nil {
		return nil, fmt.Errorf("error converting user info to unstructured: %w", err)
	}

	claimsVal, err := convertObjectToUnstructured(&c)
	if err != nil {
		return nil, fmt.Errorf("error converting claims to unstructured: %w", err)
	}

	va := &evaluationActivation{
		claims:   claimsVal.Object,
		userInfo: userInfoVal.Object,
	}

	for i, compilationResult := range m.compilationResults {
		var evaluation = &evaluations[i]
		if compilationResult.ExpressionAccessor == nil {
			continue
		}
		evaluation.ExpressionAccessor = compilationResult.ExpressionAccessor
		if compilationResult.Error != nil {
			evaluation.Error = &cel.Error{
				Type:   cel.ErrorTypeInvalid,
				Detail: fmt.Sprintf("compilation error: %v", compilationResult.Error),
			}
			continue
		}
		if compilationResult.Program == nil {
			evaluation.Error = &cel.Error{
				Type:   cel.ErrorTypeInternal,
				Detail: "unexpected internal error compiling expression",
			}
			continue
		}

		evalResult, evalDetails, err := compilationResult.Program.ContextEval(ctx, va)
		// TODO(aramase): what is composite and do we need it?
		if evalDetails == nil {
			return nil, &cel.Error{
				Type:   cel.ErrorTypeInternal,
				Detail: fmt.Sprintf("runtime cost could not be calculated for expression: %v, no further expression will be run", compilationResult.ExpressionAccessor.GetExpression()),
			}
		}

		if err != nil {
			evaluation.Error = &cel.Error{
				Type:   cel.ErrorTypeInvalid,
				Detail: fmt.Sprintf("expression '%v' resulted in error: %v", compilationResult.ExpressionAccessor.GetExpression(), err),
			}
			continue
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
