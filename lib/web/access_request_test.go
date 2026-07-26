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

// SAML-OSS fork: tests for access_request.go, the fork's access request web API.
// Upstream gates access requests behind Enterprise, so none of this is covered
// upstream.

package web

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
)

func TestMakeAccessRequestResponse_neverEmitsNullArrays(t *testing.T) {
	t.Parallel()

	// A bare request has no reviews, thresholds, resources, or suggested
	// reviewers. Each of those fields must still marshal as [] rather than null:
	// the web UI iterates them directly, and `null.map(...)` is a runtime error.
	// Go marshals a nil slice as null, so these have to be initialized empty.
	req, err := types.NewAccessRequest("req-1", "alice", "editor")
	require.NoError(t, err)

	resp := makeAccessRequestResponse(req)

	assert.NotNil(t, resp.Reviews, "Reviews must be an empty slice, not nil")
	assert.NotNil(t, resp.ThresholdNames, "ThresholdNames must be an empty slice, not nil")
	assert.NotNil(t, resp.Resources, "Resources must be an empty slice, not nil")
	assert.NotNil(t, resp.SuggestedReviewers, "SuggestedReviewers must be an empty slice, not nil")

	// Assert on the wire format, which is what the UI actually consumes.
	raw, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &decoded))

	for _, field := range []string{"reviews", "thresholdNames", "resources", "suggestedReviewers"} {
		value, ok := decoded[field]
		require.True(t, ok, "field %q missing from response", field)
		assert.JSONEq(t, "[]", string(value), "field %q must serialize as [], not null", field)
	}
}

func TestMakeAccessRequestResponse_omitsUnsetOptionalTimes(t *testing.T) {
	t.Parallel()

	req, err := types.NewAccessRequest("req-1", "alice", "editor")
	require.NoError(t, err)

	resp := makeAccessRequestResponse(req)

	// These are pointers with omitempty so the UI can distinguish "no limit"
	// from a zero timestamp. Emitting a zero time instead would render as
	// 0001-01-01 in the UI.
	assert.Nil(t, resp.MaxDuration, "MaxDuration must be omitted when unset")
	assert.Nil(t, resp.SessionTTL, "SessionTTL must be omitted when unset")

	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "maxDuration")
	assert.NotContains(t, string(raw), "sessionTTL")
	assert.NotContains(t, string(raw), "assumeStartTime")
}

func TestMakeAccessRequestResponse_includesSetOptionalTimes(t *testing.T) {
	t.Parallel()

	req, err := types.NewAccessRequest("req-1", "alice", "editor")
	require.NoError(t, err)

	maxDuration := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	sessionTTL := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	assumeStart := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)

	req.SetMaxDuration(maxDuration)
	req.SetSessionTLL(sessionTTL)
	req.SetAssumeStartTime(assumeStart)

	resp := makeAccessRequestResponse(req)

	require.NotNil(t, resp.MaxDuration)
	require.NotNil(t, resp.SessionTTL)
	require.NotNil(t, resp.AssumeStartTime)
	assert.Equal(t, maxDuration, *resp.MaxDuration)
	assert.Equal(t, sessionTTL, *resp.SessionTTL)
	assert.Equal(t, assumeStart, *resp.AssumeStartTime)
}

func TestMakeAccessRequestResponse_mapsCoreFields(t *testing.T) {
	t.Parallel()

	req, err := types.NewAccessRequest("req-42", "alice", "editor", "auditor")
	require.NoError(t, err)

	created := time.Date(2026, 6, 1, 8, 0, 0, 0, time.UTC)
	expires := time.Date(2026, 6, 2, 8, 0, 0, 0, time.UTC)
	req.SetCreationTime(created)
	req.SetAccessExpiry(expires)
	req.SetState(types.RequestState_APPROVED)
	req.SetRequestReason("need prod access")
	req.SetResolveReason("looks fine")
	req.SetSuggestedReviewers([]string{"bob", "carol"})

	resp := makeAccessRequestResponse(req)

	assert.Equal(t, "req-42", resp.ID)
	assert.Equal(t, "alice", resp.User)
	// NewAccessRequest normalizes the role list (sorted, deduped), so compare as
	// a set rather than pinning the constructor's ordering.
	assert.ElementsMatch(t, []string{"editor", "auditor"}, resp.Roles)
	assert.Equal(t, "APPROVED", resp.State)
	assert.Equal(t, created, resp.Created)
	assert.Equal(t, expires, resp.Expires)
	assert.Equal(t, "need prod access", resp.RequestReason)
	assert.Equal(t, "looks fine", resp.ResolveReason)
	assert.Equal(t, []string{"bob", "carol"}, resp.SuggestedReviewers)
}

func TestMakeAccessRequestResponse_mapsRequestedResources(t *testing.T) {
	t.Parallel()

	// Resource-based requests are what the "more views" work added to the UI;
	// every field here is rendered, so dropping one silently blanks a column.
	//
	// Note the wrapping: the constructor takes []ResourceAccessID (each holding a
	// ResourceID in Id), while GetRequestedResourceIDs returns the inner
	// []ResourceID. That asymmetry is what commit 91ac8f1 ("wrap ResourceIDs as
	// ResourceAccessIDs") had to accommodate.
	req, err := types.NewAccessRequestWithResources("req-1", "alice", []string{"editor"},
		[]types.ResourceAccessID{
			{Id: types.ResourceID{Kind: types.KindNode, Name: "node-1", ClusterName: "leaf"}},
			{Id: types.ResourceID{Kind: types.KindKubernetesCluster, Name: "kube-1", ClusterName: "root", SubResourceName: "ns/pod"}},
		})
	require.NoError(t, err)

	resp := makeAccessRequestResponse(req)

	require.Len(t, resp.Resources, 2)
	assert.Equal(t, accessRequestResourceID{
		Kind: types.KindNode, Name: "node-1", ClusterName: "leaf",
	}, resp.Resources[0].ID)
	assert.Equal(t, accessRequestResourceID{
		Kind: types.KindKubernetesCluster, Name: "kube-1", ClusterName: "root", SubResourceName: "ns/pod",
	}, resp.Resources[1].ID)
}

func TestMakeAccessRequestResponse_mapsReviews(t *testing.T) {
	t.Parallel()

	req, err := types.NewAccessRequest("req-1", "alice", "editor")
	require.NoError(t, err)

	reviewed := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	assumeStart := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	req.SetReviews([]types.AccessReview{
		{
			Author:        "bob",
			Roles:         []string{"editor"},
			ProposedState: types.RequestState_APPROVED,
			Reason:        "ok by me",
			Created:       reviewed,
		},
		{
			Author:          "carol",
			ProposedState:   types.RequestState_DENIED,
			Reason:          "no",
			Created:         reviewed,
			AssumeStartTime: &assumeStart,
		},
	})

	resp := makeAccessRequestResponse(req)

	require.Len(t, resp.Reviews, 2)

	assert.Equal(t, "bob", resp.Reviews[0].Author)
	assert.Equal(t, []string{"editor"}, resp.Reviews[0].Roles)
	assert.Equal(t, "APPROVED", resp.Reviews[0].State)
	assert.Equal(t, "ok by me", resp.Reviews[0].Reason)
	assert.Equal(t, reviewed, resp.Reviews[0].Created)
	// Only populated when the reviewer actually set one.
	assert.Nil(t, resp.Reviews[0].AssumeStartTime)

	assert.Equal(t, "carol", resp.Reviews[1].Author)
	assert.Equal(t, "DENIED", resp.Reviews[1].State)
	require.NotNil(t, resp.Reviews[1].AssumeStartTime)
	assert.Equal(t, assumeStart, *resp.Reviews[1].AssumeStartTime)
}
