/*
 * Teleport
 * Copyright (C) 2026  Gravitational, Inc.
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
	"strings"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	"github.com/gravitational/teleport/lib/httplib"
)

// matchedLogoutOrigin returns the allowlisted origin matching the request's
// Origin header, or "" if the origin is empty or not allowed. Matching is an
// exact, case-insensitive comparison; wildcards are not supported.
func (h *Handler) matchedLogoutOrigin(origin string) string {
	if origin == "" {
		return ""
	}
	for _, allowed := range h.cfg.AllowedLogoutOrigins {
		if strings.EqualFold(strings.TrimSuffix(allowed, "/"), strings.TrimSuffix(origin, "/")) {
			return origin
		}
	}
	return ""
}

// setCrossOriginLogoutHeaders sets the CORS response headers for the
// cross-origin logout endpoint. The matched origin is echoed back because
// Access-Control-Allow-Origin cannot be a wildcard when credentials are used.
func setCrossOriginLogoutHeaders(w http.ResponseWriter, origin string) {
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Add("Vary", "Origin")
}

// crossOriginLogoutPreflight handles CORS preflight requests for the
// cross-origin logout endpoint.
//
// OPTIONS /webapi/logout
func (h *Handler) crossOriginLogoutPreflight(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	origin := h.matchedLogoutOrigin(r.Header.Get("Origin"))
	if origin == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	setCrossOriginLogoutHeaders(w, origin)
	w.Header().Set("Access-Control-Allow-Methods", "DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "3600")
	w.WriteHeader(http.StatusOK)
}

// withCrossOriginLogout authenticates the cross-origin logout request.
// It requires only the session cookie (no bearer token, which other origins
// cannot obtain); CSRF protection is provided by requiring the Origin header
// to match the configured allowlist (browsers always attach Origin to
// cross-origin requests and it cannot be forged from a page). DELETE is
// also not a "simple" CORS method, so browsers will always preflight it.
func (h *Handler) withCrossOriginLogout(fn ContextHandler) httprouter.Handle {
	return httplib.MakeHandler(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
		origin := h.matchedLogoutOrigin(r.Header.Get("Origin"))
		if origin == "" {
			return nil, trace.AccessDenied("origin not allowed")
		}

		// Set CORS headers before authentication so the caller can read
		// error responses (e.g. when the session has already expired).
		setCrossOriginLogoutHeaders(w, origin)

		sctx, err := h.AuthenticateRequest(w, r, false /* validate bearer token */)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return fn(w, r, p, sctx)
	})
}

// crossOriginLogout signs the user out on behalf of an allowlisted internal
// application. It performs the same work as deleteWebSession, including
// returning the SAML single logout URL when one is configured.
//
// DELETE /webapi/logout
//
// Response: {"message": "ok"} or {"samlSloUrl": "..."}
func (h *Handler) crossOriginLogout(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext) (interface{}, error) {
	resp, err := h.deleteWebSession(w, r, p, sctx)
	return resp, trace.Wrap(err)
}
