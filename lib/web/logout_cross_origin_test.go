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
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/client"
)

func TestMatchedLogoutOrigin(t *testing.T) {
	t.Parallel()
	h := &Handler{cfg: Config{AllowedLogoutOrigins: []string{
		"https://app.internal.example.com",
		"https://other.example.com:8443",
	}}}

	for _, tc := range []struct {
		name   string
		origin string
		want   string
	}{
		{name: "allowed origin", origin: "https://app.internal.example.com", want: "https://app.internal.example.com"},
		{name: "allowed origin with port", origin: "https://other.example.com:8443", want: "https://other.example.com:8443"},
		{name: "case insensitive", origin: "https://APP.internal.example.COM", want: "https://APP.internal.example.COM"},
		{name: "empty origin", origin: "", want: ""},
		{name: "not allowed", origin: "https://evil.example.com", want: ""},
		{name: "scheme mismatch", origin: "http://app.internal.example.com", want: ""},
		{name: "port mismatch", origin: "https://other.example.com:9443", want: ""},
		{name: "prefix is not a match", origin: "https://app.internal.example.com.evil.com", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, h.matchedLogoutOrigin(tc.origin))
		})
	}
}

func TestCrossOriginLogout(t *testing.T) {
	const allowedOrigin = "https://app.internal.example.com"

	ctx := context.Background()
	t.Parallel()
	env := newWebPack(t, 1)
	proxy := env.proxies[0]
	proxy.handler.handler.cfg.AllowedLogoutOrigins = []string{allowedOrigin}

	logoutURL := proxy.webURL.String() + "/webapi/logout"

	// newRawClient returns an HTTP client carrying only the session cookies
	// (no bearer token), as a cross-origin caller would.
	newRawClient := func(t *testing.T, cookies []*http.Cookie) *http.Client {
		jar, err := cookiejar.New(nil)
		require.NoError(t, err)
		jar.SetCookies(&proxy.webURL, cookies)
		clt := client.NewInsecureWebClient()
		clt.Jar = jar
		return clt
	}

	do := func(t *testing.T, clt *http.Client, method, origin string) *http.Response {
		req, err := http.NewRequestWithContext(ctx, method, logoutURL, nil)
		require.NoError(t, err)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := clt.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		return resp
	}

	t.Run("preflight allowed origin", func(t *testing.T) {
		pack := proxy.authPack(t, "cors-logout-preflight", nil /* roles */)
		clt := newRawClient(t, pack.cookies)

		resp := do(t, clt, http.MethodOptions, allowedOrigin)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, allowedOrigin, resp.Header.Get("Access-Control-Allow-Origin"))
		require.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
		require.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "POST")
	})

	t.Run("preflight disallowed origin", func(t *testing.T) {
		clt := newRawClient(t, nil)

		resp := do(t, clt, http.MethodOptions, "https://evil.example.com")
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		require.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
	})

	t.Run("logout rejected without allowed origin", func(t *testing.T) {
		pack := proxy.authPack(t, "cors-logout-rejected", nil /* roles */)
		clt := newRawClient(t, pack.cookies)

		for _, origin := range []string{"", "https://evil.example.com"} {
			resp := do(t, clt, http.MethodPost, origin)
			require.Equal(t, http.StatusForbidden, resp.StatusCode)
			require.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
		}

		// the session must still be valid
		_, err := pack.clt.Get(ctx, pack.clt.Endpoint("webapi", "sites"), url.Values{})
		require.NoError(t, err)
	})

	t.Run("logout with allowed origin", func(t *testing.T) {
		pack := proxy.authPack(t, "cors-logout-allowed", nil /* roles */)
		clt := newRawClient(t, pack.cookies)

		resp := do(t, clt, http.MethodPost, allowedOrigin)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, allowedOrigin, resp.Header.Get("Access-Control-Allow-Origin"))
		require.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))

		// the session must be invalidated
		_, err := pack.clt.Get(ctx, pack.clt.Endpoint("webapi", "sites"), url.Values{})
		require.Error(t, err)
	})

	t.Run("logout requires session cookie", func(t *testing.T) {
		clt := newRawClient(t, nil)

		resp := do(t, clt, http.MethodPost, allowedOrigin)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		// CORS headers are set even on auth failure so the caller can read
		// the error and treat it as "already logged out"
		require.Equal(t, allowedOrigin, resp.Header.Get("Access-Control-Allow-Origin"))
	})

	t.Run("no origins configured", func(t *testing.T) {
		// not parallel: mutates the shared handler config
		orig := proxy.handler.handler.cfg.AllowedLogoutOrigins
		proxy.handler.handler.cfg.AllowedLogoutOrigins = nil
		t.Cleanup(func() { proxy.handler.handler.cfg.AllowedLogoutOrigins = orig })

		pack := proxy.authPack(t, "cors-logout-disabled", nil /* roles */)
		clt := newRawClient(t, pack.cookies)

		resp := do(t, clt, http.MethodPost, allowedOrigin)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)

		// the session must still be valid
		_, err := pack.clt.Get(ctx, pack.clt.Endpoint("webapi", "sites"), url.Values{})
		require.NoError(t, err)
	})
}
