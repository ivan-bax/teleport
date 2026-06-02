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
	"log/slog"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/types/known/emptypb"

	loginrulepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/loginrule/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/authz"
	libevents "github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
)

// ServiceConfig holds configuration options for the login rule gRPC service.
type ServiceConfig struct {
	// Authorizer is used to authorize requests.
	Authorizer authz.Authorizer
	// Backend persists login rules.
	Backend services.LoginRules
	// Emitter emits audit events.
	Emitter events.Emitter
}

// CheckAndSetDefaults validates the ServiceConfig.
func (c *ServiceConfig) CheckAndSetDefaults() error {
	if c.Authorizer == nil {
		return trace.BadParameter("authorizer is required")
	}
	if c.Backend == nil {
		return trace.BadParameter("backend is required")
	}
	if c.Emitter == nil {
		return trace.BadParameter("emitter is required")
	}
	return nil
}

// Service implements the teleport.loginrule.v1.LoginRuleService RPC service,
// backed by local cluster storage. It replaces [NotImplementedService] in open
// source builds.
type Service struct {
	loginrulepb.UnimplementedLoginRuleServiceServer

	authorizer authz.Authorizer
	backend    services.LoginRules
	emitter    events.Emitter
}

// NewService returns a new login rule gRPC service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &Service{
		authorizer: cfg.Authorizer,
		backend:    cfg.Backend,
		emitter:    cfg.Emitter,
	}, nil
}

// CreateLoginRule creates a login rule.
func (s *Service) CreateLoginRule(ctx context.Context, req *loginrulepb.CreateLoginRuleRequest) (*loginrulepb.LoginRule, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(types.KindLoginRule, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.AuthorizeAdminActionAllowReusedMFA(); err != nil {
		return nil, trace.Wrap(err)
	}

	created, err := s.backend.CreateLoginRule(ctx, req.GetLoginRule())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.emitCreateEvent(ctx, req.GetLoginRule(), authCtx)
	return created, nil
}

// UpsertLoginRule creates or replaces a login rule.
func (s *Service) UpsertLoginRule(ctx context.Context, req *loginrulepb.UpsertLoginRuleRequest) (*loginrulepb.LoginRule, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(types.KindLoginRule, types.VerbCreate, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.AuthorizeAdminActionAllowReusedMFA(); err != nil {
		return nil, trace.Wrap(err)
	}

	upserted, err := s.backend.UpsertLoginRule(ctx, req.GetLoginRule())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.emitCreateEvent(ctx, req.GetLoginRule(), authCtx)
	return upserted, nil
}

// GetLoginRule returns a login rule by name.
func (s *Service) GetLoginRule(ctx context.Context, req *loginrulepb.GetLoginRuleRequest) (*loginrulepb.LoginRule, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(types.KindLoginRule, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	rule, err := s.backend.GetLoginRule(ctx, req.GetName())
	return rule, trace.Wrap(err)
}

// ListLoginRules returns a paginated list of login rules.
func (s *Service) ListLoginRules(ctx context.Context, req *loginrulepb.ListLoginRulesRequest) (*loginrulepb.ListLoginRulesResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(types.KindLoginRule, types.VerbRead, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}

	rules, nextToken, err := s.backend.ListLoginRules(ctx, int(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &loginrulepb.ListLoginRulesResponse{
		LoginRules:    rules,
		NextPageToken: nextToken,
	}, nil
}

// DeleteLoginRule deletes a login rule by name.
func (s *Service) DeleteLoginRule(ctx context.Context, req *loginrulepb.DeleteLoginRuleRequest) (*emptypb.Empty, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(types.KindLoginRule, types.VerbDelete); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.AuthorizeAdminActionAllowReusedMFA(); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.backend.DeleteLoginRule(ctx, req.GetName()); err != nil {
		return nil, trace.Wrap(err)
	}
	s.emitDeleteEvent(ctx, req.GetName(), authCtx)
	return &emptypb.Empty{}, nil
}

// TestLoginRule evaluates the supplied login rules (optionally combined with the
// rules stored in the cluster) against the supplied traits and returns the
// resulting traits without persisting anything.
func (s *Service) TestLoginRule(ctx context.Context, req *loginrulepb.TestLoginRuleRequest) (*loginrulepb.TestLoginRuleResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// Testing a rule requires the same level of access as creating one, since
	// it can be used to evaluate arbitrary, unsaved rules against cluster data.
	if err := authCtx.CheckAccessToKind(types.KindLoginRule, types.VerbCreate, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}

	// Build the set of rules to evaluate. Supplied rules take precedence over
	// any cluster rule with the same name.
	rulesByName := make(map[string]*loginrulepb.LoginRule)
	if req.GetLoadFromCluster() {
		clusterRules, err := listAllLoginRules(ctx, s.backend)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		for _, rule := range clusterRules {
			rulesByName[rule.GetMetadata().GetName()] = rule
		}
	}
	for _, rule := range req.GetLoginRules() {
		rulesByName[rule.GetMetadata().GetName()] = rule
	}
	rules := make([]*loginrulepb.LoginRule, 0, len(rulesByName))
	for _, rule := range rulesByName {
		rules = append(rules, rule)
	}

	output, err := evaluateRules(&loginrule.EvaluationInput{
		Traits: traitsToStringSlice(req.GetTraits()),
	}, rules)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &loginrulepb.TestLoginRuleResponse{
		Traits: stringSliceToTraits(output.Traits),
	}, nil
}

func (s *Service) emitCreateEvent(ctx context.Context, rule *loginrulepb.LoginRule, authCtx *authz.Context) {
	if auditErr := s.emitter.EmitAuditEvent(ctx, &events.LoginRuleCreate{
		Metadata: events.Metadata{
			Type: libevents.LoginRuleCreateEvent,
			Code: libevents.LoginRuleCreateCode,
		},
		UserMetadata: authCtx.GetUserMetadata(),
		ResourceMetadata: events.ResourceMetadata{
			Name:      rule.GetMetadata().GetName(),
			UpdatedBy: authCtx.Identity.GetIdentity().Username,
		},
	}); auditErr != nil {
		slog.WarnContext(ctx, "Failed to emit login rule create event.", "error", auditErr)
	}
}

func (s *Service) emitDeleteEvent(ctx context.Context, name string, authCtx *authz.Context) {
	if auditErr := s.emitter.EmitAuditEvent(ctx, &events.LoginRuleDelete{
		Metadata: events.Metadata{
			Type: libevents.LoginRuleDeleteEvent,
			Code: libevents.LoginRuleDeleteCode,
		},
		UserMetadata: authCtx.GetUserMetadata(),
		ResourceMetadata: events.ResourceMetadata{
			Name:      name,
			UpdatedBy: authCtx.Identity.GetIdentity().Username,
		},
	}); auditErr != nil {
		slog.WarnContext(ctx, "Failed to emit login rule delete event.", "error", auditErr)
	}
}

// traitsToStringSlice converts the wire trait representation to a plain string
// slice map.
func traitsToStringSlice(m map[string]*wrappers.StringValues) map[string][]string {
	out := make(map[string][]string, len(m))
	for key, values := range m {
		if values != nil {
			out[key] = values.Values
		}
	}
	return out
}

// stringSliceToTraits converts a plain string slice map to the wire trait
// representation.
func stringSliceToTraits(m map[string][]string) map[string]*wrappers.StringValues {
	out := make(map[string]*wrappers.StringValues, len(m))
	for key, values := range m {
		out[key] = &wrappers.StringValues{Values: values}
	}
	return out
}
