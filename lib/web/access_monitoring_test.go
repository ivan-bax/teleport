/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
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

// SAML-OSS fork: tests for access_monitoring.go, the fork's access monitoring
// rule web API. Upstream gates access monitoring behind Enterprise, so none of
// this is covered upstream.

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accessmonitoringrulesv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/accessmonitoringrules/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
)

// accessMonitoringRuleRole returns a role granting full access to access
// monitoring rules, which the web handlers require.
func accessMonitoringRuleRole(t *testing.T) types.Role {
	t.Helper()
	role, err := types.NewRole("amr-admin", types.RoleSpecV6{
		Allow: types.RoleConditions{
			Rules: []types.Rule{
				types.NewRule(types.KindAccessMonitoringRule,
					[]string{types.VerbList, types.VerbRead, types.VerbCreate, types.VerbUpdate, types.VerbDelete}),
			},
		},
	})
	require.NoError(t, err)
	return role
}

func newTestAccessMonitoringRule(t *testing.T, name string) *accessmonitoringrulesv1.AccessMonitoringRule {
	t.Helper()
	// A rule subject to access_request must configure notification or
	// automatic_review. automatic_review with the builtin integration is the
	// shape this fork's auto-approval path uses.
	rule, err := services.NewAccessMonitoringRuleWithLabels(name, nil, &accessmonitoringrulesv1.AccessMonitoringRuleSpec{
		Subjects:     []string{types.KindAccessRequest},
		Condition:    `access_request.spec.roles.contains("editor")`,
		DesiredState: types.AccessMonitoringRuleStateReviewed,
		AutomaticReview: &accessmonitoringrulesv1.AutomaticReview{
			Integration: "builtin",
			Decision:    types.RequestState_APPROVED.String(),
		},
	})
	require.NoError(t, err)
	return rule
}

// TestListAccessMonitoringRules_paginatesBeyondOnePage is the reason this file
// has tests. listAccessMonitoringRules loops over backend pages of
// accessMonitoringRulesPageSize, and the web UI has no pagination of its own, so
// a broken loop silently shows only the first page — rules would appear to have
// vanished, and auto-approval rules that exist would look absent.
func TestListAccessMonitoringRules_paginatesBeyondOnePage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	pack := proxy.authPack(t, "amr-user@example.com", []types.Role{accessMonitoringRuleRole(t)})

	// One and a half pages, so a loop that returns early is caught.
	const total = accessMonitoringRulesPageSize + 50
	want := make([]string, 0, total)
	for i := range total {
		name := fmt.Sprintf("rule-%03d", i)
		_, err := env.server.Auth().CreateAccessMonitoringRule(ctx, newTestAccessMonitoringRule(t, name))
		require.NoError(t, err)
		want = append(want, name)
	}

	re, err := pack.clt.Get(ctx, pack.clt.Endpoint("webapi", "accessmonitoringrules"), nil)
	require.NoError(t, err)

	var resp accessMonitoringRulesListResponse
	require.NoError(t, json.Unmarshal(re.Bytes(), &resp))

	got := make([]string, 0, len(resp.Items))
	for _, item := range resp.Items {
		got = append(got, item.GetMetadata().GetName())
	}
	assert.Len(t, got, total, "every page must be accumulated, not just the first")
	assert.ElementsMatch(t, want, got)
}

func TestAccessMonitoringRules_createUpdateDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	pack := proxy.authPack(t, "amr-user@example.com", []types.Role{accessMonitoringRuleRole(t)})

	endpoint := pack.clt.Endpoint("webapi", "accessmonitoringrules")

	// Create.
	rule := newTestAccessMonitoringRule(t, "my-rule")
	_, err := pack.clt.PostJSON(ctx, endpoint, rule)
	require.NoError(t, err)

	stored, err := env.server.Auth().GetAccessMonitoringRule(ctx, "my-rule")
	require.NoError(t, err)
	assert.Equal(t, `access_request.spec.roles.contains("editor")`, stored.GetSpec().GetCondition())

	// Update, via the upsert path.
	rule.Spec.Condition = `access_request.spec.roles.contains("auditor")`
	_, err = pack.clt.PutJSON(ctx, endpoint+"/my-rule", rule)
	require.NoError(t, err)

	stored, err = env.server.Auth().GetAccessMonitoringRule(ctx, "my-rule")
	require.NoError(t, err)
	assert.Equal(t, `access_request.spec.roles.contains("auditor")`,
		stored.GetSpec().GetCondition(), "update must persist the new condition")

	// Delete.
	_, err = pack.clt.Delete(ctx, endpoint+"/my-rule")
	require.NoError(t, err)

	_, err = env.server.Auth().GetAccessMonitoringRule(ctx, "my-rule")
	assert.Error(t, err, "rule should be gone after delete")
}

func TestAccessMonitoringRules_requiresRBAC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	// No access_monitoring_rule verbs: these rules drive automatic approval of
	// privilege grants, so an unprivileged user must not be able to read or
	// change them.
	pack := proxy.authPack(t, "plain-user@example.com", nil /* roles */)

	endpoint := pack.clt.Endpoint("webapi", "accessmonitoringrules")

	_, err := pack.clt.Get(ctx, endpoint, nil)
	require.Error(t, err)
	assert.True(t, trace.IsAccessDenied(err), "expected AccessDenied listing rules, got %v", err)

	_, err = pack.clt.PostJSON(ctx, endpoint, newTestAccessMonitoringRule(t, "sneaky"))
	require.Error(t, err)
	assert.True(t, trace.IsAccessDenied(err), "expected AccessDenied creating a rule, got %v", err)

	_, err = env.server.Auth().GetAccessMonitoringRule(ctx, "sneaky")
	assert.Error(t, err, "rule must not have been created")
}
