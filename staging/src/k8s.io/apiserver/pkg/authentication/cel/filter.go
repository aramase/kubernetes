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
	"math"
	"time"

	"github.com/google/cel-go/interpreter"
	"k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

// filterCompiler implement the interface FilterCompiler.
type filterCompiler struct {
	compiler Compiler
}

func NewFilterCompiler(env *environment.EnvSet) FilterCompiler {
	return &filterCompiler{compiler: NewCompiler(env)}
}

type evaluationActivation struct {
	claims interface{}
}

// ResolveName returns a value from the activation by qualified name, or false if the name
// could not be found.
func (a *evaluationActivation) ResolveName(name string) (interface{}, bool) {
	switch name {
	case ClaimsVarName:
		return a.claims, true
	default:
		return nil, false
	}
}

// Parent returns the parent of the current activation, may be nil.
// If non-nil, the parent will be searched during resolve calls.
func (a *evaluationActivation) Parent() interpreter.Activation {
	return nil
}

// Compile compiles the cel expressions defined in the ExpressionAccessors into a Filter
func (c *filterCompiler) Compile(expressionAccessors []ExpressionAccessor, mode environment.Type) Filter {
	compilationResults := make([]CompilationResult, len(expressionAccessors))
	for i, expressionAccessor := range expressionAccessors {
		if expressionAccessor == nil {
			continue
		}
		compilationResults[i] = c.compiler.CompileCELExpression(expressionAccessor, mode)
	}
	return NewFilter(compilationResults)
}

// filter implements the Filter interface
type filter struct {
	compilationResults []CompilationResult
}

func NewFilter(compilationResults []CompilationResult) Filter {
	return &filter{
		compilationResults,
	}
}

// ForInput evaluates the compiled CEL expressions converting them into CELEvaluations
// errors per evaluation are returned on the Evaluation object
// runtimeCELCostBudget was added for testing purpose only. Callers should always use const RuntimeCELCostBudget from k8s.io/apiserver/pkg/apis/cel/config.go as input.
func (f *filter) ForInput(ctx context.Context, claims map[string]interface{}, runtimeCELCostBudget int64) ([]EvaluationResult, int64, error) {
	evaluations := make([]EvaluationResult, len(f.compilationResults))

	va := &evaluationActivation{
		claims: claims,
	}

	remainingBudget := runtimeCELCostBudget
	for i, compilationResult := range f.compilationResults {
		var evaluation = &evaluations[i]
		if compilationResult.ExpressionAccessor == nil { // in case of placeholder
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
				Detail: fmt.Sprintf("unexpected internal error compiling expression"),
			}
			continue
		}
		t1 := time.Now()
		evalResult, evalDetails, err := compilationResult.Program.ContextEval(ctx, va)
		elapsed := time.Since(t1)
		evaluation.Elapsed = elapsed
		if evalDetails == nil {
			return nil, -1, &cel.Error{
				Type:   cel.ErrorTypeInternal,
				Detail: fmt.Sprintf("runtime cost could not be calculated for expression: %v, no further expression will be run", compilationResult.ExpressionAccessor.GetExpression()),
			}
		} else {
			rtCost := evalDetails.ActualCost()
			if rtCost == nil {
				return nil, -1, &cel.Error{
					Type:   cel.ErrorTypeInvalid,
					Detail: fmt.Sprintf("runtime cost could not be calculated for expression: %v, no further expression will be run", compilationResult.ExpressionAccessor.GetExpression()),
				}
			} else {
				if *rtCost > math.MaxInt64 || int64(*rtCost) > remainingBudget {
					return nil, -1, &cel.Error{
						Type:   cel.ErrorTypeInvalid,
						Detail: fmt.Sprintf("validation failed due to running out of cost budget, no further validation rules will be run"),
					}
				}
				remainingBudget -= int64(*rtCost)
			}
		}
		if err != nil {
			evaluation.Error = &cel.Error{
				Type:   cel.ErrorTypeInvalid,
				Detail: fmt.Sprintf("expression '%v' resulted in error: %v", compilationResult.ExpressionAccessor.GetExpression(), err),
			}
		} else {
			evaluation.EvalResult = evalResult
		}
	}

	return evaluations, remainingBudget, nil
}

// CompilationErrors returns a list of all the errors from the compilation of the evaluator
func (e *filter) CompilationErrors() []error {
	compilationErrors := []error{}
	for _, result := range e.compilationResults {
		if result.Error != nil {
			compilationErrors = append(compilationErrors, result.Error)
		}
	}
	return compilationErrors
}
