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

	"k8s.io/apimachinery/pkg/util/version"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

const (
	ClaimsVarName = "claims"
)

// CompilationResult represents a compiled validations expression.
type CompilationResult struct {
	Program            cel.Program
	Error              *apiservercel.Error
	ExpressionAccessor ExpressionAccessor
}

// Compiler provides a CEL expression compiler configured with the desired admission related CEL variables and
// environment mode.
type Compiler interface {
	CompileCELExpression(expressionAccessor ExpressionAccessor, mode environment.Type) CompilationResult
}

type compiler struct {
	env *environment.EnvSet
}

func NewCompiler(env *environment.EnvSet) Compiler {
	return &compiler{env: mustBuildEnvs(env)}
}

// CompileCELExpression returns a compiled CEL expression.
// perCallLimit was added for testing purpose only. Callers should always use const PerCallLimit from k8s.io/apiserver/pkg/apis/cel/config.go as input.
func (c compiler) CompileCELExpression(expressionAccessor ExpressionAccessor, envType environment.Type) CompilationResult {
	resultError := func(errorString string, errType apiservercel.ErrorType) CompilationResult {
		return CompilationResult{
			Error: &apiservercel.Error{
				Type:   errType,
				Detail: errorString,
			},
			ExpressionAccessor: expressionAccessor,
		}
	}

	env, err := c.env.Env(envType)
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
		if ast.OutputType() == returnType {
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
	_, err = cel.AstToCheckedExpr(ast)
	if err != nil {
		// should be impossible since env.Compile returned no issues
		return resultError("unexpected compilation error: "+err.Error(), apiservercel.ErrorTypeInternal)
	}
	prog, err := env.Program(ast,
		cel.InterruptCheckFrequency(celconfig.CheckFrequency),
	)
	if err != nil {
		return resultError("program instantiation failed: "+err.Error(), apiservercel.ErrorTypeInternal)
	}
	return CompilationResult{
		Program:            prog,
		ExpressionAccessor: expressionAccessor,
	}
}

func mustBuildEnvs(baseEnv *environment.EnvSet) *environment.EnvSet {
	var envOpts []cel.EnvOption
	envOpts = append(envOpts,
		cel.Variable(ClaimsVarName, cel.DynType),
	)

	extended, err := baseEnv.Extend(
		environment.VersionedOptions{
			// Feature epoch was actually 1.26, but we artificially set it to 1.0 because these
			// options should always be present.
			IntroducedVersion: version.MajorMinor(1, 0),
			EnvOptions:        envOpts,
		},
	)
	if err != nil {
		panic(fmt.Sprintf("environment misconfigured: %v", err))
	}
	return extended
}
