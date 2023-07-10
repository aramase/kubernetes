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
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"k8s.io/apiserver/pkg/cel/environment"
)

type ExpressionAccessor interface {
	GetExpression() string
	ReturnTypes() []*cel.Type
}

// EvaluationResult contains the minimal required fields and metadata of a cel evaluation
type EvaluationResult struct {
	EvalResult         ref.Val
	ExpressionAccessor ExpressionAccessor
	Elapsed            time.Duration
	Error              error
}

// FilterCompiler contains a function to assist with converting types and values to/from CEL-typed values.
type FilterCompiler interface {
	// Compile is used for the cel expression compilation
	Compile(expressions []ExpressionAccessor, envType environment.Type) Filter
}

// Filter contains a function to evaluate compiled CEL-typed values
// It expects the inbound object to already have been converted to the version expected
// by the underlying CEL code (which is indicated by the match criteria of a policy definition).
// versionedParams may be nil.
type Filter interface {
	// ForInput converts compiled CEL-typed values into evaluated CEL-typed value.
	// runtimeCELCostBudget was added for testing purpose only. Callers should always use const RuntimeCELCostBudget from k8s.io/apiserver/pkg/apis/cel/config.go as input.
	// If cost budget is calculated, the filter should return the remaining budget.
	ForInput(ctx context.Context, claims map[string]interface{}, runtimeCELCostBudget int64) ([]EvaluationResult, int64, error)

	// CompilationErrors returns a list of errors from the compilation of the evaluator
	CompilationErrors() []error
}
