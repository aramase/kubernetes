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
	ExpressionAccessor ExpressionAccessor
}

// Compiler provides a CEL expression compiler configured with the desired authentication related CEL variables.
type Compiler interface {
	CompileCELExpression(expressionAccessor ExpressionAccessor, variable string) (CompilationResult, error)
}

type compiler struct {
	varEnvs map[string]*environment.EnvSet
}

// NewCompiler returns a new Compiler.
func NewCompiler(env *environment.EnvSet) Compiler {
	return &compiler{
		varEnvs: mustBuildEnvs(env),
	}
}

// CompileCELExpression compiles the given expression and returns a CompilationResult.
// The compilation error is stored in the CompilationResult if the expression is invalid
func (c compiler) CompileCELExpression(expressionAccessor ExpressionAccessor, envVarName string) (CompilationResult, error) {
	resultError := func(errorString string, errType apiservercel.ErrorType) (CompilationResult, error) {
		return CompilationResult{}, &apiservercel.Error{
			Type:   errType,
			Detail: errorString,
		}
	}

	env, err := c.varEnvs[envVarName].Env(environment.StoredExpressions)
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
	}, nil
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

func mustBuildEnvs(baseEnv *environment.EnvSet) map[string]*environment.EnvSet {
	buildEnvSet := func(envOpts []cel.EnvOption, declTypes []*apiservercel.DeclType) *environment.EnvSet {
		env, err := baseEnv.Extend(environment.VersionedOptions{
			IntroducedVersion: version.MajorMinor(1, 0),
			EnvOptions:        envOpts,
			DeclTypes:         declTypes,
		})
		if err != nil {
			panic(fmt.Sprintf("environment misconfigured: %v", err))
		}
		return env
	}

	userType := buildUserType()
	claimsType := apiservercel.NewMapType(apiservercel.StringType, apiservercel.AnyType, -1)

	envs := make(map[string]*environment.EnvSet, 2) // build two environments, one for claims and one for user
	envs[ClaimsVarName] = buildEnvSet([]cel.EnvOption{cel.Variable(ClaimsVarName, claimsType.CelType())}, []*apiservercel.DeclType{claimsType})
	envs[UserVarName] = buildEnvSet([]cel.EnvOption{cel.Variable(UserVarName, userType.CelType())}, []*apiservercel.DeclType{userType})

	return envs
}
