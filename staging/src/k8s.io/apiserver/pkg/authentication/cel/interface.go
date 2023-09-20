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

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
)

type ExpressionAccessor interface {
	GetExpression() string
	ReturnTypes() []*celgo.Type
}

// EvaluationResult contains the minimal required fields and metadata of a cel evaluation
type EvaluationResult struct {
	EvalResult         ref.Val
	ExpressionAccessor ExpressionAccessor
}

// Mapper provides a CEL expression mapper configured with the desired authentication related CEL variables.
type Mapper interface {
	Eval(ctx context.Context, claims, userInfo interface{}) ([]EvaluationResult, error)
}

var _ ExpressionAccessor = &ClaimMappingCondition{}

// ClaimMappingCondition is a CEL expression that maps a claim.
type ClaimMappingCondition struct {
	Expression string
}

func (v *ClaimMappingCondition) GetExpression() string {
	return v.Expression
}

func (v *ClaimMappingCondition) ReturnTypes() []*celgo.Type {
	// return types is only used for validation. The claims variable that's available
	// to the claim mapping expressions is a map[string]interface{}, so we can't
	// really know what the return type is during compilation. Strict type checking
	// is done during evaluation.
	return []*celgo.Type{celgo.AnyType}
}

var _ ExpressionAccessor = &ClaimValidationCondition{}

// ClaimValidationCondition is a CEL expression that validates a claim.
type ClaimValidationCondition struct {
	Expression string
	Message    string
}

func (v *ClaimValidationCondition) GetExpression() string {
	return v.Expression
}

func (v *ClaimValidationCondition) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.BoolType}
}

var _ ExpressionAccessor = &ExtraMappingCondition{}

// ExtraMappingCondition is a CEL expression that maps an extra to a list of values.
type ExtraMappingCondition struct {
	Key        string
	Expression string
}

func (v *ExtraMappingCondition) GetExpression() string {
	return v.Expression
}

func (v *ExtraMappingCondition) ReturnTypes() []*celgo.Type {
	// return types is only used for validation. The claims variable that's available
	// to the claim mapping expressions is a map[string]interface{}, so we can't
	// really know what the return type is during compilation. Strict type checking
	// is done during evaluation.
	return []*celgo.Type{celgo.AnyType}
}

var _ ExpressionAccessor = &UserValidationCondition{}

// UserValidationCondition is a CEL expression that validates a User.
type UserValidationCondition struct {
	Expression string
	Message    string
}

func (v *UserValidationCondition) GetExpression() string {
	return v.Expression
}

func (v *UserValidationCondition) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.BoolType}
}
