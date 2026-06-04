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

package web

import (
	"net/http"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	accessmonitoringrulesv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/accessmonitoringrules/v1"
	"github.com/gravitational/teleport/lib/httplib"
)

// accessMonitoringRulesPageSize is the number of rules fetched per backend page
// while listing all access monitoring rules.
const accessMonitoringRulesPageSize = 100

// listAccessMonitoringRules returns every access monitoring rule stored in the
// cluster.
//
// GET /webapi/accessmonitoringrules
func (h *Handler) listAccessMonitoringRules(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	ctx := r.Context()

	clt, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	amrClient := clt.AccessMonitoringRuleClient()

	var rules []*accessmonitoringrulesv1.AccessMonitoringRule
	var pageToken string
	for {
		page, nextToken, err := amrClient.ListAccessMonitoringRules(ctx, accessMonitoringRulesPageSize, pageToken)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		rules = append(rules, page...)
		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return accessMonitoringRulesListResponse{Items: rules}, nil
}

type accessMonitoringRulesListResponse struct {
	Items []*accessmonitoringrulesv1.AccessMonitoringRule `json:"items"`
}

// createAccessMonitoringRule creates a new access monitoring rule from the
// resource JSON in the request body.
//
// POST /webapi/accessmonitoringrules
func (h *Handler) createAccessMonitoringRule(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	ctx := r.Context()

	var rule accessmonitoringrulesv1.AccessMonitoringRule
	if err := httplib.ReadResourceJSON(r, &rule); err != nil {
		return nil, trace.Wrap(err)
	}

	clt, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	created, err := clt.AccessMonitoringRuleClient().CreateAccessMonitoringRule(ctx, &rule)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return created, nil
}

// updateAccessMonitoringRule upserts the access monitoring rule named in the
// path with the resource JSON in the request body.
//
// PUT /webapi/accessmonitoringrules/:name
func (h *Handler) updateAccessMonitoringRule(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	ctx := r.Context()

	name := p.ByName("name")
	if name == "" {
		return nil, trace.BadParameter("missing access monitoring rule name")
	}

	var rule accessmonitoringrulesv1.AccessMonitoringRule
	if err := httplib.ReadResourceJSON(r, &rule); err != nil {
		return nil, trace.Wrap(err)
	}

	clt, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	updated, err := clt.AccessMonitoringRuleClient().UpsertAccessMonitoringRule(ctx, &rule)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return updated, nil
}

// deleteAccessMonitoringRule deletes the access monitoring rule named in the
// path.
//
// DELETE /webapi/accessmonitoringrules/:name
func (h *Handler) deleteAccessMonitoringRule(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (any, error) {
	ctx := r.Context()

	name := p.ByName("name")
	if name == "" {
		return nil, trace.BadParameter("missing access monitoring rule name")
	}

	clt, err := sctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := clt.AccessMonitoringRuleClient().DeleteAccessMonitoringRule(ctx, name); err != nil {
		return nil, trace.Wrap(err)
	}

	return OK(), nil
}
