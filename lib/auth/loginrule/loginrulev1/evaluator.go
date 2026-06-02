/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package loginrulev1

import (
	"context"
	"sort"

	"github.com/gravitational/trace"

	loginrulepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/loginrule/v1"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/expression"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils/typical"
)

// Evaluator is a [loginrule.Evaluator] which loads all login rules currently
// stored in the cluster and applies them to the input traits in priority order.
type Evaluator struct {
	backend services.LoginRules
}

// NewEvaluator returns a login rule evaluator backed by the given store.
func NewEvaluator(backend services.LoginRules) *Evaluator {
	return &Evaluator{backend: backend}
}

// Evaluate loads all login rules from the backend and applies them to the
// input traits.
func (e *Evaluator) Evaluate(ctx context.Context, input *loginrule.EvaluationInput) (*loginrule.EvaluationOutput, error) {
	rules, err := listAllLoginRules(ctx, e.backend)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	output, err := evaluateRules(input, rules)
	return output, trace.Wrap(err)
}

// listAllLoginRules pages through every login rule stored in the backend.
func listAllLoginRules(ctx context.Context, backend services.LoginRules) ([]*loginrulepb.LoginRule, error) {
	var rules []*loginrulepb.LoginRule
	var pageToken string
	for {
		page, nextToken, err := backend.ListLoginRules(ctx, 0, pageToken)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		rules = append(rules, page...)
		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}
	return rules, nil
}

// evaluationEnv is the environment available to login rule predicate
// expressions. The user's current traits are exposed under the "external"
// variable, supporting access like external.groups or external["email"].
type evaluationEnv struct {
	external expression.Dict
}

// newParser builds a traits expression parser whose expressions evaluate
// against an [evaluationEnv].
func newParser() (*typical.Parser[evaluationEnv, any], error) {
	parser, err := expression.NewTraitsExpressionParser[evaluationEnv](map[string]typical.Variable{
		"external": typical.DynamicMap[evaluationEnv, expression.Set](func(env evaluationEnv) (expression.Dict, error) {
			return env.external, nil
		}),
	})
	return parser, trace.Wrap(err)
}

// evaluateRules applies the given login rules to the input traits. Rules are
// applied in ascending priority order (ties broken by name); the output traits
// of each rule become the input of the next. The names of all applied rules
// are returned in evaluation order.
func evaluateRules(input *loginrule.EvaluationInput, rules []*loginrulepb.LoginRule) (*loginrule.EvaluationOutput, error) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].GetPriority() != rules[j].GetPriority() {
			return rules[i].GetPriority() < rules[j].GetPriority()
		}
		return rules[i].GetMetadata().GetName() < rules[j].GetMetadata().GetName()
	})

	parser, err := newParser()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	traits := input.Traits
	appliedRules := make([]string, 0, len(rules))
	for _, rule := range rules {
		next, err := applyRule(parser, rule, traits)
		if err != nil {
			return nil, trace.Wrap(err, "evaluating login rule %q", rule.GetMetadata().GetName())
		}
		traits = next
		appliedRules = append(appliedRules, rule.GetMetadata().GetName())
	}

	return &loginrule.EvaluationOutput{
		Traits:       traits,
		AppliedRules: appliedRules,
	}, nil
}

// applyRule applies a single login rule to the given traits and returns the
// resulting traits. A rule sets either traits_map or traits_expression
// (enforced during validation).
func applyRule(parser *typical.Parser[evaluationEnv, any], rule *loginrulepb.LoginRule, traits map[string][]string) (map[string][]string, error) {
	env := evaluationEnv{external: expression.DictFromStringSliceMap(traits)}

	switch {
	case rule.GetTraitsExpression() != "":
		expr, err := parser.Parse(rule.GetTraitsExpression())
		if err != nil {
			return nil, trace.Wrap(err, "parsing traits_expression")
		}
		result, err := expr.Evaluate(env)
		if err != nil {
			return nil, trace.Wrap(err, "evaluating traits_expression")
		}
		dict, ok := result.(expression.Dict)
		if !ok {
			return nil, trace.BadParameter("traits_expression must evaluate to a dict, got %T", result)
		}
		return expression.StringSliceMapFromDict(dict), nil

	case len(rule.GetTraitsMap()) > 0:
		dict, err := expression.EvaluateTraitsMap(env, traitsMapExpressions(rule.GetTraitsMap()),
			func(input string) (typical.Expression[evaluationEnv, any], error) {
				expr, err := parser.Parse(input)
				return expr, trace.Wrap(err)
			})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return expression.StringSliceMapFromDict(dict), nil

	default:
		return traits, nil
	}
}

// traitsMapExpressions converts a login rule's traits_map (trait name to a list
// of predicate expressions) into the plain string map expected by
// [expression.EvaluateTraitsMap].
func traitsMapExpressions(m map[string]*wrappers.StringValues) map[string][]string {
	out := make(map[string][]string, len(m))
	for key, values := range m {
		if values != nil {
			out[key] = values.Values
		}
	}
	return out
}
