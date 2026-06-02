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

package loginrulev1_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	loginrulepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/loginrule/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/auth/loginrule/loginrulev1"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
)

func newBackend(t *testing.T) services.LoginRules {
	t.Helper()
	b, err := memory.New(memory.Config{
		Context: context.Background(),
		Clock:   clockwork.NewFakeClock(),
	})
	require.NoError(t, err)
	service, err := local.NewLoginRuleService(b)
	require.NoError(t, err)
	return service
}

func mapRule(name string, priority int32, traitsMap map[string][]string) *loginrulepb.LoginRule {
	m := make(map[string]*wrappers.StringValues, len(traitsMap))
	for k, v := range traitsMap {
		m[k] = &wrappers.StringValues{Values: v}
	}
	return &loginrulepb.LoginRule{
		Metadata:  &types.Metadata{Name: name},
		Version:   types.V1,
		Priority:  priority,
		TraitsMap: m,
	}
}

func exprRule(name string, priority int32, expression string) *loginrulepb.LoginRule {
	return &loginrulepb.LoginRule{
		Metadata:         &types.Metadata{Name: name},
		Version:          types.V1,
		Priority:         priority,
		TraitsExpression: expression,
	}
}

func TestEvaluator(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	inputTraits := map[string][]string{
		"groups": {"devs", "admins"},
		"email":  {"alice@example.com"},
	}

	tests := []struct {
		name     string
		rules    []*loginrulepb.LoginRule
		expected map[string][]string
		// applied is the expected applied-rule names in evaluation order.
		applied []string
	}{
		{
			name: "traits_map replaces traits with literal and referenced values",
			rules: []*loginrulepb.LoginRule{
				mapRule("map", 0, map[string][]string{
					"groups": {"external.groups", "everyone"},
					"logins": {"ubuntu"},
				}),
			},
			expected: map[string][]string{
				"groups": {"admins", "devs", "everyone"},
				"logins": {"ubuntu"},
			},
			applied: []string{"map"},
		},
		{
			name: "traits_expression mutates the external dict in place",
			rules: []*loginrulepb.LoginRule{
				exprRule("expr", 0, `external.add_values("groups", "everyone")`),
			},
			expected: map[string][]string{
				"groups": {"admins", "devs", "everyone"},
				"email":  {"alice@example.com"},
			},
			applied: []string{"expr"},
		},
		{
			name: "rules apply in priority order and feed forward",
			rules: []*loginrulepb.LoginRule{
				// Lower priority runs first: keep only groups+logins.
				mapRule("second", 10, map[string][]string{
					"groups": {"external.groups"},
					"logins": {"external.logins"},
				}),
				exprRule("first", 1, `external.add_values("logins", "root")`),
			},
			expected: map[string][]string{
				"groups": {"admins", "devs"},
				"logins": {"root"},
			},
			applied: []string{"first", "second"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backend := newBackend(t)
			for _, rule := range tc.rules {
				_, err := backend.CreateLoginRule(ctx, rule)
				require.NoError(t, err)
			}

			evaluator := loginrulev1.NewEvaluator(backend)
			output, err := evaluator.Evaluate(ctx, &loginrule.EvaluationInput{Traits: inputTraits})
			require.NoError(t, err)

			require.Empty(t, cmp.Diff(tc.expected, output.Traits,
				cmpopts.SortSlices(func(a, b string) bool { return a < b })))
			require.Equal(t, tc.applied, output.AppliedRules)
		})
	}
}

func TestEvaluatorNoRules(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	input := map[string][]string{"groups": {"devs"}}
	evaluator := loginrulev1.NewEvaluator(newBackend(t))
	output, err := evaluator.Evaluate(ctx, &loginrule.EvaluationInput{Traits: input})
	require.NoError(t, err)
	require.Equal(t, input, output.Traits)
	require.Empty(t, output.AppliedRules)
}
