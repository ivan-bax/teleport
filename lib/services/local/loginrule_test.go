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
	"fmt"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	loginrulepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/loginrule/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/services"
)

func newLoginRuleService(t *testing.T) services.LoginRules {
	t.Helper()
	backend, err := memory.New(memory.Config{
		Context: context.Background(),
		Clock:   clockwork.NewFakeClock(),
	})
	require.NoError(t, err)

	service, err := NewLoginRuleService(backend)
	require.NoError(t, err)
	return service
}

func newTestLoginRule(name string, priority int32) *loginrulepb.LoginRule {
	return &loginrulepb.LoginRule{
		Metadata: &types.Metadata{Name: name},
		Version:  types.V1,
		Priority: priority,
		TraitsMap: map[string]*wrappers.StringValues{
			"groups": {Values: []string{"external.groups", "teleport"}},
		},
	}
}

func TestLoginRuleServiceCRUD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := newLoginRuleService(t)

	// Create.
	created, err := service.CreateLoginRule(ctx, newTestLoginRule("rule-1", 0))
	require.NoError(t, err)
	require.NotEmpty(t, created.GetMetadata().GetRevision(), "revision should be populated on create")

	// Creating a duplicate fails.
	_, err = service.CreateLoginRule(ctx, newTestLoginRule("rule-1", 0))
	require.True(t, trace.IsAlreadyExists(err), "expected AlreadyExists, got %v", err)

	// Get.
	got, err := service.GetLoginRule(ctx, "rule-1")
	require.NoError(t, err)
	require.Equal(t, "rule-1", got.GetMetadata().GetName())
	require.Equal(t, []string{"external.groups", "teleport"}, got.GetTraitsMap()["groups"].Values)

	// Get of a missing rule fails.
	_, err = service.GetLoginRule(ctx, "missing")
	require.True(t, trace.IsNotFound(err), "expected NotFound, got %v", err)

	// Upsert (replace) an existing rule.
	updated := newTestLoginRule("rule-1", 5)
	upserted, err := service.UpsertLoginRule(ctx, updated)
	require.NoError(t, err)
	require.Equal(t, int32(5), upserted.GetPriority())

	// Upsert (create) a new rule.
	_, err = service.UpsertLoginRule(ctx, newTestLoginRule("rule-2", 1))
	require.NoError(t, err)

	// Delete.
	require.NoError(t, service.DeleteLoginRule(ctx, "rule-1"))
	_, err = service.GetLoginRule(ctx, "rule-1")
	require.True(t, trace.IsNotFound(err))

	// DeleteAll.
	require.NoError(t, service.DeleteAllLoginRules(ctx))
	rules, _, err := service.ListLoginRules(ctx, 0, "")
	require.NoError(t, err)
	require.Empty(t, rules)
}

func TestLoginRuleServiceListPagination(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := newLoginRuleService(t)

	const total = 7
	for i := range total {
		_, err := service.CreateLoginRule(ctx, newTestLoginRule(fmt.Sprintf("rule-%02d", i), int32(i)))
		require.NoError(t, err)
	}

	var collected []string
	var pageToken string
	for {
		page, next, err := service.ListLoginRules(ctx, 3, pageToken)
		require.NoError(t, err)
		require.LessOrEqual(t, len(page), 3)
		for _, rule := range page {
			collected = append(collected, rule.GetMetadata().GetName())
		}
		if next == "" {
			break
		}
		pageToken = next
	}
	require.Len(t, collected, total)
}

func TestLoginRuleServiceExpiryRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := newLoginRuleService(t)

	expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	rule := newTestLoginRule("expiring", 0)
	rule.Metadata.SetExpiry(expiry)

	_, err := service.CreateLoginRule(ctx, rule)
	require.NoError(t, err)

	got, err := service.GetLoginRule(ctx, "expiring")
	require.NoError(t, err)
	require.WithinDuration(t, expiry, got.GetMetadata().Expiry(), time.Second)
}

func TestLoginRuleServiceValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service := newLoginRuleService(t)

	// Neither traits_map nor traits_expression set.
	empty := &loginrulepb.LoginRule{
		Metadata: &types.Metadata{Name: "empty"},
		Version:  types.V1,
	}
	_, err := service.CreateLoginRule(ctx, empty)
	require.True(t, trace.IsBadParameter(err), "expected BadParameter, got %v", err)

	// Both traits_map and traits_expression set.
	both := newTestLoginRule("both", 0)
	both.TraitsExpression = `external.put("logins", external.groups)`
	_, err = service.CreateLoginRule(ctx, both)
	require.True(t, trace.IsBadParameter(err), "expected BadParameter, got %v", err)

	// Missing name.
	noName := newTestLoginRule("", 0)
	_, err = service.CreateLoginRule(ctx, noName)
	require.True(t, trace.IsBadParameter(err), "expected BadParameter, got %v", err)
}
