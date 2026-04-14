/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

package web

import (
	"net/http"
	"time"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/httplib"
)

// accessRequestResponse is the JSON representation of an access request
// for the web UI frontend.
type accessRequestResponse struct {
	ID                 string                   `json:"id"`
	State              string                   `json:"state"`
	User               string                   `json:"user"`
	Roles              []string                 `json:"roles"`
	Created            time.Time                `json:"created"`
	Expires            time.Time                `json:"expires"`
	MaxDuration        *time.Time               `json:"maxDuration,omitempty"`
	RequestTTL         time.Time                `json:"requestTTL"`
	SessionTTL         *time.Time               `json:"sessionTTL,omitempty"`
	RequestReason      string                   `json:"requestReason"`
	ResolveReason      string                   `json:"resolveReason"`
	Reviews            []accessReviewResponse   `json:"reviews"`
	SuggestedReviewers []string                 `json:"suggestedReviewers"`
	ThresholdNames     []string                 `json:"thresholdNames"`
	Resources          []accessRequestResource  `json:"resources"`
	AssumeStartTime    *time.Time               `json:"assumeStartTime,omitempty"`
}

type accessReviewResponse struct {
	Author          string     `json:"author"`
	Roles           []string   `json:"roles"`
	State           string     `json:"state"`
	Reason          string     `json:"reason"`
	Created         time.Time  `json:"created"`
	AssumeStartTime *time.Time `json:"assumeStartTime,omitempty"`
}

type accessRequestResource struct {
	ID      accessRequestResourceID      `json:"id"`
	Details *accessRequestResourceDetail `json:"details,omitempty"`
}

type accessRequestResourceID struct {
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	ClusterName     string `json:"clusterName"`
	SubResourceName string `json:"subResourceName,omitempty"`
}

type accessRequestResourceDetail struct {
	FriendlyName string `json:"friendlyName,omitempty"`
}

func makeAccessRequestResponse(req types.AccessRequest) accessRequestResponse {
	reviews := make([]accessReviewResponse, 0)
	for _, r := range req.GetReviews() {
		rev := accessReviewResponse{
			Author:  r.Author,
			Roles:   r.Roles,
			State:   r.ProposedState.String(),
			Reason:  r.Reason,
			Created: r.Created,
		}
		if r.AssumeStartTime != nil {
			rev.AssumeStartTime = r.AssumeStartTime
		}
		reviews = append(reviews, rev)
	}

	thresholdNames := make([]string, 0)
	for _, t := range req.GetThresholds() {
		thresholdNames = append(thresholdNames, t.Name)
	}

	resources := make([]accessRequestResource, 0)
	for _, r := range req.GetRequestedResourceIDs() {
		resources = append(resources, accessRequestResource{
			ID: accessRequestResourceID{
				Kind:            r.Kind,
				Name:            r.Name,
				ClusterName:     r.ClusterName,
				SubResourceName: r.SubResourceName,
			},
		})
	}

	suggestedReviewers := req.GetSuggestedReviewers()
	if suggestedReviewers == nil {
		suggestedReviewers = []string{}
	}

	resp := accessRequestResponse{
		ID:                 req.GetName(),
		State:              req.GetState().String(),
		User:               req.GetUser(),
		Roles:              req.GetRoles(),
		Created:            req.GetCreationTime(),
		Expires:            req.GetAccessExpiry(),
		RequestTTL:         req.Expiry(),
		RequestReason:      req.GetRequestReason(),
		ResolveReason:      req.GetResolveReason(),
		Reviews:            reviews,
		SuggestedReviewers: suggestedReviewers,
		ThresholdNames:     thresholdNames,
		Resources:          resources,
	}

	if maxDur := req.GetMaxDuration(); !maxDur.IsZero() {
		resp.MaxDuration = &maxDur
	}
	if sessionTTL := req.GetSessionTLL(); !sessionTTL.IsZero() {
		resp.SessionTTL = &sessionTTL
	}
	resp.AssumeStartTime = req.GetAssumeStartTime()

	return resp
}

// getAccessRequests returns a list of access requests.
//
// GET /enterprise/accessrequest
func (h *Handler) getAccessRequests(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	ctx := r.Context()
	clt, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	requests, err := clt.GetAccessRequests(ctx, types.AccessRequestFilter{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resp := make([]accessRequestResponse, 0, len(requests))
	for _, req := range requests {
		resp = append(resp, makeAccessRequestResponse(req))
	}

	return resp, nil
}

// getAccessRequest returns a single access request by ID.
//
// GET /enterprise/accessrequest/:requestId
func (h *Handler) getAccessRequest(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	ctx := r.Context()
	requestID := p.ByName("requestId")
	if requestID == "" {
		return nil, trace.BadParameter("missing request ID")
	}

	clt, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	requests, err := clt.GetAccessRequests(ctx, types.AccessRequestFilter{
		ID: requestID,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(requests) == 0 {
		return nil, trace.NotFound("access request %q not found", requestID)
	}

	return makeAccessRequestResponse(requests[0]), nil
}

type createAccessRequestRequest struct {
	Roles              []string              `json:"roles"`
	ResourceIDs        []accessRequestResReq `json:"resourceIds"`
	Reason             string                `json:"reason"`
	SuggestedReviewers []string              `json:"suggestedReviewers"`
	MaxDuration        *time.Time            `json:"maxDuration,omitempty"`
	DryRun             bool                  `json:"dryRun"`
}

type accessRequestResReq struct {
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	ClusterName     string `json:"clusterName"`
	SubResourceName string `json:"subResourceName,omitempty"`
}

// createAccessRequest creates a new access request.
//
// POST /enterprise/accessrequest
func (h *Handler) createAccessRequest(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	ctx := r.Context()

	var req createAccessRequestRequest
	if err := httplib.ReadResourceJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	clt, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var resourceIDs []types.ResourceID
	for _, r := range req.ResourceIDs {
		resourceIDs = append(resourceIDs, types.ResourceID{
			Kind:            r.Kind,
			Name:            r.Name,
			ClusterName:     r.ClusterName,
			SubResourceName: r.SubResourceName,
		})
	}

	accessReq, err := types.NewAccessRequestWithResources(
		"", // empty name, server generates UUID
		sctx.GetUser(),
		req.Roles,
		resourceIDs,
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	accessReq.SetRequestReason(req.Reason)
	accessReq.SetSuggestedReviewers(req.SuggestedReviewers)
	if req.MaxDuration != nil {
		accessReq.SetMaxDuration(*req.MaxDuration)
	}
	accessReq.SetDryRun(req.DryRun)

	created, err := clt.CreateAccessRequestV2(ctx, accessReq)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return makeAccessRequestResponse(created), nil
}

// deleteAccessRequest deletes an access request.
//
// DELETE /enterprise/accessrequest/:requestId
func (h *Handler) deleteAccessRequest(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	ctx := r.Context()
	requestID := p.ByName("requestId")
	if requestID == "" {
		return nil, trace.BadParameter("missing request ID")
	}

	clt, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := clt.DeleteAccessRequest(ctx, requestID); err != nil {
		return nil, trace.Wrap(err)
	}

	return OK(), nil
}

type updateAccessRequestStateRequest struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

// updateAccessRequestState updates the state of an access request (approve/deny).
//
// PUT /enterprise/accessrequest/:requestId
func (h *Handler) updateAccessRequestState(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	ctx := r.Context()
	requestID := p.ByName("requestId")
	if requestID == "" {
		return nil, trace.BadParameter("missing request ID")
	}

	var req updateAccessRequestStateRequest
	if err := httplib.ReadResourceJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	var state types.RequestState
	switch req.State {
	case "APPROVED":
		state = types.RequestState_APPROVED
	case "DENIED":
		state = types.RequestState_DENIED
	default:
		return nil, trace.BadParameter("unsupported state %q, must be APPROVED or DENIED", req.State)
	}

	clt, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := clt.SetAccessRequestState(ctx, types.AccessRequestUpdate{
		RequestID: requestID,
		State:     state,
		Reason:    req.Reason,
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	return OK(), nil
}

type submitAccessReviewRequest struct {
	State           string     `json:"state"`
	Reason          string     `json:"reason"`
	Roles           []string   `json:"roles"`
	AssumeStartTime *time.Time `json:"assumeStartTime,omitempty"`
}

// submitAccessReview submits a review for an access request.
//
// POST /enterprise/accessrequest/:requestId/review
func (h *Handler) submitAccessReview(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	ctx := r.Context()
	requestID := p.ByName("requestId")
	if requestID == "" {
		return nil, trace.BadParameter("missing request ID")
	}

	var req submitAccessReviewRequest
	if err := httplib.ReadResourceJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	var state types.RequestState
	switch req.State {
	case "APPROVED":
		state = types.RequestState_APPROVED
	case "DENIED":
		state = types.RequestState_DENIED
	default:
		return nil, trace.BadParameter("unsupported review state %q, must be APPROVED or DENIED", req.State)
	}

	clt, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	updated, err := clt.SubmitAccessReview(ctx, types.AccessReviewSubmission{
		RequestID: requestID,
		Review: types.AccessReview{
			Author:          sctx.GetUser(),
			ProposedState:   state,
			Reason:          req.Reason,
			Roles:           req.Roles,
			AssumeStartTime: req.AssumeStartTime,
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return makeAccessRequestResponse(updated), nil
}
