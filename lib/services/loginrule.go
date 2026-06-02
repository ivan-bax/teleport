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

package services

import (
	"context"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	loginrulepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/loginrule/v1"
	"github.com/gravitational/teleport/api/types"
)

// LoginRules defines an interface for managing login rule resources.
type LoginRules interface {
	// CreateLoginRule creates a login rule, returning an error if a rule with
	// the same name already exists.
	CreateLoginRule(ctx context.Context, rule *loginrulepb.LoginRule) (*loginrulepb.LoginRule, error)
	// UpsertLoginRule creates or replaces a login rule.
	UpsertLoginRule(ctx context.Context, rule *loginrulepb.LoginRule) (*loginrulepb.LoginRule, error)
	// GetLoginRule fetches a single login rule by name.
	GetLoginRule(ctx context.Context, name string) (*loginrulepb.LoginRule, error)
	// ListLoginRules returns a paginated list of all login rules.
	ListLoginRules(ctx context.Context, pageSize int, pageToken string) ([]*loginrulepb.LoginRule, string, error)
	// DeleteLoginRule deletes a single login rule by name.
	DeleteLoginRule(ctx context.Context, name string) error
	// DeleteAllLoginRules deletes all login rules.
	DeleteAllLoginRules(ctx context.Context) error
}

// MarshalLoginRule marshals a [loginrulepb.LoginRule] to JSON.
//
// LoginRule embeds the legacy [types.Metadata] rather than the RFD 153
// header metadata, so it cannot use [MarshalProtoResource]; the revision is
// reset on the legacy metadata instead.
func MarshalLoginRule(rule *loginrulepb.LoginRule, opts ...MarshalOption) ([]byte, error) {
	if rule == nil {
		return nil, trace.BadParameter("login rule is nil")
	}
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if !cfg.PreserveRevision && rule.GetMetadata().GetRevision() != "" {
		rule = proto.Clone(rule).(*loginrulepb.LoginRule)
		rule.Metadata.Revision = ""
	}
	data, err := protojson.Marshal(rule)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return data, nil
}

// UnmarshalLoginRule unmarshals a [loginrulepb.LoginRule] from JSON.
func UnmarshalLoginRule(data []byte, opts ...MarshalOption) (*loginrulepb.LoginRule, error) {
	if len(data) == 0 {
		return nil, trace.BadParameter("missing login rule data")
	}
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var rule loginrulepb.LoginRule
	if err := (protojson.UnmarshalOptions{DiscardUnknown: !cfg.DisallowUnknown}).Unmarshal(data, &rule); err != nil {
		return nil, trace.Wrap(err)
	}
	if rule.Metadata == nil {
		rule.Metadata = &types.Metadata{}
	}
	if cfg.Revision != "" {
		rule.Metadata.Revision = cfg.Revision
	}
	if !cfg.Expires.IsZero() {
		rule.Metadata.SetExpiry(cfg.Expires)
	}
	return &rule, nil
}
