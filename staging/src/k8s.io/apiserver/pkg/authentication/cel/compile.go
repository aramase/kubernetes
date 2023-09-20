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
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"

	"k8s.io/apimachinery/pkg/util/version"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

const (
	ClaimsVarName = "claims"
	UserVarName   = "user"
)

// CompilationResult represents a compiled validations expression.
type CompilationResult struct {
	Program            cel.Program
	Error              *apiservercel.Error
	ExpressionAccessor ExpressionAccessor
}

// EvaluationResult contains the minimal required fields and metadata of a cel evaluation
type EvaluationResult struct {
	EvalResult         ref.Val
	ExpressionAccessor ExpressionAccessor
	Error              error
}

// Compiler is an interface for compiling CEL expressions with the desired environment mode.
type Compiler interface {
	CompileCELExpression(expressionAccessor ExpressionAccessor, mode environment.Type) CompilationResult
}

type compiler struct {
	envSet *environment.EnvSet
}

// NewCompiler returns a new Compiler.
func NewCompiler(env *environment.EnvSet) Compiler {
	return &compiler{
		envSet: mustBuildEnv(env),
	}
}

func (c compiler) CompileCELExpression(expressionAccessor ExpressionAccessor, mode environment.Type) CompilationResult {
	resultError := func(errorString string, errType apiservercel.ErrorType) CompilationResult {
		return CompilationResult{
			Error: &apiservercel.Error{
				Type:   errType,
				Detail: errorString,
			},
			ExpressionAccessor: expressionAccessor,
		}
	}

	env, err := c.envSet.Env(mode)
	if err != nil {
		return resultError(fmt.Sprintf("unexpected error loading CEL environment: %v", err), apiservercel.ErrorTypeInternal)
	}

	ast, issues := env.Compile(expressionAccessor.GetExpression())
	if issues != nil {
		return resultError("compilation failed: "+issues.String(), apiservercel.ErrorTypeInvalid)
	}

	found := false
	returnTypes := expressionAccessor.ReturnTypes()
	for _, returnType := range returnTypes {
		if ast.OutputType() == returnType || cel.AnyType == returnType {
			found = true
			break
		}
	}
	if !found {
		var reason string
		if len(returnTypes) == 1 {
			reason = fmt.Sprintf("must evaluate to %v", returnTypes[0].String())
		} else {
			reason = fmt.Sprintf("must evaluate to one of %v", returnTypes)
		}

		return resultError(reason, apiservercel.ErrorTypeInvalid)
	}

	if _, err = cel.AstToCheckedExpr(ast); err != nil {
		// should be impossible since env.Compile returned no issues
		return resultError("unexpected compilation error: "+err.Error(), apiservercel.ErrorTypeInternal)
	}
	prog, err := env.Program(ast)
	if err != nil {
		return resultError("program instantiation failed: "+err.Error(), apiservercel.ErrorTypeInternal)
	}

	return CompilationResult{
		Program:            prog,
		ExpressionAccessor: expressionAccessor,
	}
}

func buildUserType() *apiservercel.DeclType {
	field := func(name string, declType *apiservercel.DeclType, required bool) *apiservercel.DeclField {
		return apiservercel.NewDeclField(name, declType, required, nil, nil)
	}
	fields := func(fields ...*apiservercel.DeclField) map[string]*apiservercel.DeclField {
		result := make(map[string]*apiservercel.DeclField, len(fields))
		for _, f := range fields {
			result[f.Name] = f
		}
		return result
	}

	return apiservercel.NewObjectType("kubernetes.UserInfo", fields(
		field("username", apiservercel.StringType, false),
		field("uid", apiservercel.StringType, false),
		field("groups", apiservercel.NewListType(apiservercel.StringType, -1), false),
		field("extra", apiservercel.NewMapType(apiservercel.StringType, apiservercel.NewListType(apiservercel.StringType, -1), -1), false),
	))
}

func mustBuildEnv(baseEnv *environment.EnvSet) *environment.EnvSet {
	userType := buildUserType()

	extended, err := baseEnv.Extend(
		environment.VersionedOptions{
			// Feature epoch was actually 1.26, but we artificially set it to 1.0 because these
			// options should always be present.
			// TODO(aramase): this is set similar to compile.go in admission/cel. Need to validate.
			IntroducedVersion: version.MajorMinor(1, 0),
			EnvOptions: []cel.EnvOption{
				cel.Variable(ClaimsVarName, cel.DynType),
				cel.Variable(UserVarName, userType.CelType()),
			},
			DeclTypes: []*apiservercel.DeclType{
				userType,
			},
		},
	)

	if err != nil {
		panic(fmt.Sprintf("environment misconfigured: %v", err))
	}

	return extended
}
