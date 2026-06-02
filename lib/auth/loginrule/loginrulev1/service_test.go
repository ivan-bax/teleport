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
	"slices"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	loginrulepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/loginrule/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/auth/loginrule/loginrulev1"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/tlsca"
)

type fakeChecker struct {
	allowedVerbs []string
	services.AccessChecker
}

func (f fakeChecker) CheckAccessToRule(_ services.RuleContext, _ string, resource string, verb string) error {
	if resource == types.KindLoginRule && slices.Contains(f.allowedVerbs, verb) {
		return nil
	}
	return trace.AccessDenied("access denied to rule=%v/verb=%v", resource, verb)
}

func newServiceWithChecker(t *testing.T, state authz.AdminActionAuthState, checker services.AccessChecker) (*loginrulev1.Service, services.LoginRules) {
	t.Helper()

	b, err := memory.New(memory.Config{})
	require.NoError(t, err)
	backendService, err := local.NewLoginRuleService(b)
	require.NoError(t, err)

	authorizer := authz.AuthorizerFunc(func(ctx context.Context) (*authz.Context, error) {
		user, err := types.NewUser("llama")
		if err != nil {
			return nil, err
		}
		return &authz.Context{
			User:                 user,
			Checker:              checker,
			AdminActionAuthState: state,
			Identity: authz.LocalUser{
				Identity: tlsca.Identity{Username: user.GetName()},
			},
		}, nil
	})

	service, err := loginrulev1.NewService(loginrulev1.ServiceConfig{
		Authorizer: authorizer,
		Backend:    backendService,
		Emitter:    events.NewDiscardEmitter(),
	})
	require.NoError(t, err)
	return service, backendService
}

func TestServiceAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testCases := []struct {
		name         string
		allowedVerbs []string
		call         func(s *loginrulev1.Service) error
	}{
		{
			name:         "CreateLoginRule",
			allowedVerbs: []string{types.VerbCreate},
			call: func(s *loginrulev1.Service) error {
				_, err := s.CreateLoginRule(ctx, &loginrulepb.CreateLoginRuleRequest{LoginRule: testRule("create")})
				return err
			},
		},
		{
			name:         "UpsertLoginRule",
			allowedVerbs: []string{types.VerbCreate, types.VerbUpdate},
			call: func(s *loginrulev1.Service) error {
				_, err := s.UpsertLoginRule(ctx, &loginrulepb.UpsertLoginRuleRequest{LoginRule: testRule("upsert")})
				return err
			},
		},
		{
			name:         "GetLoginRule",
			allowedVerbs: []string{types.VerbRead},
			call: func(s *loginrulev1.Service) error {
				_, err := s.GetLoginRule(ctx, &loginrulepb.GetLoginRuleRequest{Name: "missing"})
				return err
			},
		},
		{
			name:         "ListLoginRules",
			allowedVerbs: []string{types.VerbRead, types.VerbList},
			call: func(s *loginrulev1.Service) error {
				_, err := s.ListLoginRules(ctx, &loginrulepb.ListLoginRulesRequest{})
				return err
			},
		},
		{
			name:         "DeleteLoginRule",
			allowedVerbs: []string{types.VerbDelete},
			call: func(s *loginrulev1.Service) error {
				_, err := s.DeleteLoginRule(ctx, &loginrulepb.DeleteLoginRuleRequest{Name: "missing"})
				return err
			},
		},
		{
			name:         "TestLoginRule",
			allowedVerbs: []string{types.VerbCreate, types.VerbUpdate},
			call: func(s *loginrulev1.Service) error {
				_, err := s.TestLoginRule(ctx, &loginrulepb.TestLoginRuleRequest{})
				return err
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// With the required verbs the request is authorized (it may still
			// fail for other reasons, but never with access denied).
			t.Run("allowed", func(t *testing.T) {
				service, _ := newServiceWithChecker(t, authz.AdminActionAuthNotRequired, fakeChecker{allowedVerbs: tc.allowedVerbs})
				err := tc.call(service)
				require.False(t, trace.IsAccessDenied(err), "unexpected access denied: %v", err)
			})

			// With no verbs the request is denied.
			t.Run("denied without verbs", func(t *testing.T) {
				service, _ := newServiceWithChecker(t, authz.AdminActionAuthNotRequired, fakeChecker{})
				err := tc.call(service)
				require.True(t, trace.IsAccessDenied(err), "expected access denied, got %v", err)
			})
		})
	}
}

func TestMutationRequiresAdminAction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	service, backend := newServiceWithChecker(t, authz.AdminActionAuthUnauthorized,
		fakeChecker{allowedVerbs: []string{types.VerbCreate, types.VerbUpdate, types.VerbDelete}})

	_, err := service.CreateLoginRule(ctx, &loginrulepb.CreateLoginRuleRequest{LoginRule: testRule("rule")})
	require.True(t, trace.IsAccessDenied(err), "create without admin action should be denied, got %v", err)

	rules, _, err := backend.ListLoginRules(ctx, 0, "")
	require.NoError(t, err)
	require.Empty(t, rules, "no rule should have been persisted")
}

func TestTestLoginRuleDoesNotPersist(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	service, backend := newServiceWithChecker(t, authz.AdminActionAuthNotRequired,
		fakeChecker{allowedVerbs: []string{types.VerbCreate, types.VerbUpdate}})

	resp, err := service.TestLoginRule(ctx, &loginrulepb.TestLoginRuleRequest{
		LoginRules: []*loginrulepb.LoginRule{testRule("ephemeral")},
		Traits: map[string]*wrappers.StringValues{
			"groups": {Values: []string{"devs"}},
		},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"devs", "teleport"}, resp.GetTraits()["groups"].Values)

	// Nothing should have been written to the backend.
	rules, _, err := backend.ListLoginRules(ctx, 0, "")
	require.NoError(t, err)
	require.Empty(t, rules)
}

func testRule(name string) *loginrulepb.LoginRule {
	return &loginrulepb.LoginRule{
		Metadata: &types.Metadata{Name: name},
		Version:  types.V1,
		TraitsMap: map[string]*wrappers.StringValues{
			"groups": {Values: []string{"external.groups", "teleport"}},
		},
	}
}
