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

package local

import (
	"context"
	"time"

	"github.com/gravitational/trace"

	loginrulepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/loginrule/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local/generic"
)

const loginRulePrefix = "login_rule"

// loginRuleAdapter wraps a [loginrulepb.LoginRule] so it satisfies the legacy
// [types.Resource] interface required by the generic backend service. The
// generated proto embeds the legacy [types.Metadata] (which already provides
// name/expiry/revision accessors), so the adapter only needs to supply the
// kind/subkind/version methods and return metadata by value.
type loginRuleAdapter struct {
	*loginrulepb.LoginRule
}

func (r loginRuleAdapter) GetKind() string     { return types.KindLoginRule }
func (r loginRuleAdapter) GetSubKind() string  { return "" }
func (r loginRuleAdapter) SetSubKind(string)   {}
func (r loginRuleAdapter) GetName() string     { return r.LoginRule.GetMetadata().GetName() }
func (r loginRuleAdapter) SetName(name string) { r.LoginRule.Metadata.SetName(name) }
func (r loginRuleAdapter) Expiry() time.Time   { return r.LoginRule.Metadata.Expiry() }
func (r loginRuleAdapter) SetExpiry(t time.Time) {
	r.LoginRule.Metadata.SetExpiry(t)
}
func (r loginRuleAdapter) GetMetadata() types.Metadata { return *r.LoginRule.Metadata }
func (r loginRuleAdapter) GetRevision() string         { return r.LoginRule.Metadata.GetRevision() }
func (r loginRuleAdapter) SetRevision(rev string)      { r.LoginRule.Metadata.SetRevision(rev) }

// LoginRuleService is the local backend implementation of the
// [services.LoginRules] interface.
type LoginRuleService struct {
	service *generic.Service[loginRuleAdapter]
}

// NewLoginRuleService returns a new login rule backend service.
func NewLoginRuleService(b backend.Backend) (*LoginRuleService, error) {
	service, err := generic.NewService(&generic.ServiceConfig[loginRuleAdapter]{
		Backend:       b,
		ResourceKind:  types.KindLoginRule,
		PageLimit:     defaults.MaxIterationLimit,
		BackendPrefix: backend.NewKey(loginRulePrefix),
		MarshalFunc: func(rule loginRuleAdapter, opts ...services.MarshalOption) ([]byte, error) {
			return services.MarshalLoginRule(rule.LoginRule, opts...)
		},
		UnmarshalFunc: func(data []byte, opts ...services.MarshalOption) (loginRuleAdapter, error) {
			rule, err := services.UnmarshalLoginRule(data, opts...)
			return loginRuleAdapter{rule}, trace.Wrap(err)
		},
		ValidateFunc: func(rule loginRuleAdapter) error {
			return validateLoginRule(rule.LoginRule)
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &LoginRuleService{service: service}, nil
}

// CreateLoginRule creates a login rule if one with the same name does not
// already exist.
func (s *LoginRuleService) CreateLoginRule(ctx context.Context, rule *loginrulepb.LoginRule) (*loginrulepb.LoginRule, error) {
	created, err := s.service.CreateResource(ctx, loginRuleAdapter{rule})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return created.LoginRule, nil
}

// UpsertLoginRule creates or replaces a login rule.
func (s *LoginRuleService) UpsertLoginRule(ctx context.Context, rule *loginrulepb.LoginRule) (*loginrulepb.LoginRule, error) {
	upserted, err := s.service.UpsertResource(ctx, loginRuleAdapter{rule})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return upserted.LoginRule, nil
}

// GetLoginRule returns the login rule with the given name.
func (s *LoginRuleService) GetLoginRule(ctx context.Context, name string) (*loginrulepb.LoginRule, error) {
	rule, err := s.service.GetResource(ctx, name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return rule.LoginRule, nil
}

// ListLoginRules returns a paginated list of all login rules.
func (s *LoginRuleService) ListLoginRules(ctx context.Context, pageSize int, pageToken string) ([]*loginrulepb.LoginRule, string, error) {
	adapters, next, err := s.service.ListResources(ctx, pageSize, pageToken)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	rules := make([]*loginrulepb.LoginRule, 0, len(adapters))
	for _, a := range adapters {
		rules = append(rules, a.LoginRule)
	}
	return rules, next, nil
}

// DeleteLoginRule deletes the login rule with the given name.
func (s *LoginRuleService) DeleteLoginRule(ctx context.Context, name string) error {
	return trace.Wrap(s.service.DeleteResource(ctx, name))
}

// DeleteAllLoginRules deletes all login rules.
func (s *LoginRuleService) DeleteAllLoginRules(ctx context.Context) error {
	return trace.Wrap(s.service.DeleteAllResources(ctx))
}

// validateLoginRule checks that a login rule is well formed before it is
// persisted. Exactly one of traits_map or traits_expression must be set.
func validateLoginRule(rule *loginrulepb.LoginRule) error {
	if rule == nil {
		return trace.BadParameter("login rule is nil")
	}
	if rule.Metadata == nil || rule.Metadata.Name == "" {
		return trace.BadParameter("login rule is missing metadata.name")
	}
	if rule.Version == "" {
		rule.Version = types.V1
	}
	hasMap := len(rule.TraitsMap) > 0
	hasExpression := rule.TraitsExpression != ""
	switch {
	case hasMap && hasExpression:
		return trace.BadParameter("login rule has non-empty traits_map and traits_expression, exactly one must be set")
	case !hasMap && !hasExpression:
		return trace.BadParameter("login rule has empty traits_map and traits_expression, exactly one must be set")
	}
	return nil
}
