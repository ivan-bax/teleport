// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package web

import (
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	devicepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/web/app"
)

// deviceWebConfirm is the last step in device web authentication, where the
// "authenticator process" (aka Connect) forwards the DeviceConfirmationToken
// back to the Auth Server, via the Proxy.
//
// GET /webapi/devices/webconfirm?id=a&token=b
//
// - id: ID of the confirmation token.
// - token: raw confirmation token.
//
// The result of this call is a redirect to "/web", regardless of the outcome of
// the ConfirmDeviceWebAuthentication RPC.
func (h *Handler) deviceWebConfirm(w http.ResponseWriter, r *http.Request, _ httprouter.Params, sessionCtx *SessionContext) (interface{}, error) {
	query := r.URL.Query()

	// Read input parameters.
	confirmToken := &devicepb.DeviceConfirmationToken{}
	confirmToken.Id = query.Get("id")
	confirmToken.Token = query.Get("token")
	unsafeRedirectURI := query.Get("redirect_uri")

	switch {
	case confirmToken.Id == "":
		return nil, trace.BadParameter("parameter id required")
	case confirmToken.Token == "":
		return nil, trace.BadParameter("parameter token required")
	}

	// Use the Proxy identity for this call. Only the Proxy is allowed to do it.
	devicesClient := h.GetProxyClient().DevicesClient()
	ctx := r.Context()

	_, err := devicesClient.ConfirmDeviceWebAuthentication(ctx, &devicepb.ConfirmDeviceWebAuthenticationRequest{
		ConfirmationToken:   confirmToken,
		CurrentWebSessionId: sessionCtx.GetSessionID(),
	})
	switch {
	case err != nil:
		h.logger.WarnContext(ctx, "Device web authentication confirm failed",
			"error", err,
			"user", sessionCtx.GetUser(),
		)
		// err swallowed on purpose.
	default:
		// Preemptively release session from cache, as its certificates are now
		// updated.
		// The WebSession watcher takes care of this in other proxy instances
		// (see [sessionCache.watchWebSessions]).
		h.auth.releaseResources(r.Context(), sessionCtx.GetUser(), sessionCtx.GetSessionID())
	}

	// Always redirect back to the dashboard, regardless of outcome.
	app.SetRedirectPageHeaders(w.Header(), "" /* nonce */)

	redirectTo, err := h.getRedirectURL(r.Host, unsafeRedirectURI)
	if err != nil {
		h.logger.DebugContext(ctx, "Unable to parse redirectURI",
			"error", err,
			"redirect_uri", unsafeRedirectURI,
		)
		http.Error(w, http.StatusText(trace.ErrorToCode(err)), trace.ErrorToCode(err))
		return nil, nil
	}
	http.Redirect(w, r, redirectTo, http.StatusSeeOther)

	return nil, nil
}

// getRedirectPath tries to parse the given unsafeRedirectURI.
// It returns a full URL if the unsafeRedirectURI points to SAML IdP SSO endpoint.
// In any other case, as long as the redirect URL is parsable, it returns
// a path ensuring its prefixed with "/web".
//
// Nobody seems to know why we need to prepend the base path to the URL, so we keep doing it. It
// might be related to the URLs we get from SSO redirects [1], but it's unclear why we'd be getting
// a URL that's missing the base path and becomes valid only after appending the base path.
//
// [1]: https://github.com/gravitational/teleport/pull/47221#discussion_r1792248868
func (h *Handler) getRedirectURL(host, unsafeRedirectURI string) (string, error) {
	const (
		basePath                = "/web"
		samlSPInitiatedSSOPath  = "/enterprise/saml-idp/sso"
		samlIDPInitiatedSSOPath = "/enterprise/saml-idp/login"
	)

	if unsafeRedirectURI == "" {
		return basePath, nil
	}

	parsedURL, err := url.Parse(unsafeRedirectURI)
	if err != nil {
		return basePath, trace.BadParameter("invalid redirect URL")
	}

	cleanPath := path.Clean(parsedURL.Path)
	// helps in situations where there is no path such as https://example.com
	if cleanPath == "." || cleanPath == ".." {
		cleanPath = "/"
	} else if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}

	// IDP initiated SSO path format: "/enterprise/saml-idp/login/<service provider name>"
	isIdpInitiatedSSOPath := strings.HasPrefix(cleanPath, samlIDPInitiatedSSOPath) && len(strings.Split(cleanPath, "/")) == 5
	if cleanPath == samlSPInitiatedSSOPath || isIdpInitiatedSSOPath {
		if parsedURL.Host != host {
			return "", trace.BadParameter("host mismatch")
		}
		path := samlSPInitiatedSSOPath
		if isIdpInitiatedSSOPath {
			path = cleanPath
		}
		ensuredURL := &url.URL{
			Scheme:   "https",
			Host:     host,
			Path:     path,
			RawQuery: parsedURL.RawQuery,
		}
		return ensuredURL.String(), nil
	}

	// Prepend "/web" only if it's not already present
	if !strings.HasPrefix(cleanPath, basePath) {
		cleanPath = path.Join(basePath, cleanPath)
	}

	if parsedURL.RawQuery != "" {
		return cleanPath + "?" + parsedURL.RawQuery, nil
	}
	return cleanPath, nil
}

// listDevicesHandle returns a paginated list of trusted devices.
//
// GET /webapi/devices/list?limit=N&startKey=TOKEN
func (h *Handler) listDevicesHandle(_ http.ResponseWriter, r *http.Request, _ httprouter.Params, ctx *SessionContext) (interface{}, error) {
	clt, err := ctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	values := r.URL.Query()
	limit, err := QueryLimitAsInt32(values, "limit", defaults.MaxIterationLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	startKey := values.Get("startKey")

	resp, err := clt.DevicesClient().ListDevices(r.Context(), &devicepb.ListDevicesRequest{
		PageSize:  limit,
		PageToken: startKey,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	items := make([]deviceJSON, 0, len(resp.Devices))
	for _, d := range resp.Devices {
		items = append(items, deviceToJSON(d))
	}

	return &listResourcesWithoutCountGetResponse{
		Items:    items,
		StartKey: resp.NextPageToken,
	}, nil
}

type deviceJSON struct {
	ID           string `json:"id"`
	AssetTag     string `json:"assetTag"`
	OSType       string `json:"osType"`
	EnrollStatus string `json:"enrollStatus"`
	Owner        string `json:"owner"`
}

func deviceToJSON(d *devicepb.Device) deviceJSON {
	var osType string
	switch d.OsType {
	case devicepb.OSType_OS_TYPE_LINUX:
		osType = "Linux"
	case devicepb.OSType_OS_TYPE_MACOS:
		osType = "macOS"
	case devicepb.OSType_OS_TYPE_WINDOWS:
		osType = "Windows"
	default:
		osType = "unknown"
	}

	var enrollStatus string
	switch d.EnrollStatus {
	case devicepb.DeviceEnrollStatus_DEVICE_ENROLL_STATUS_ENROLLED:
		enrollStatus = "enrolled"
	case devicepb.DeviceEnrollStatus_DEVICE_ENROLL_STATUS_NOT_ENROLLED:
		enrollStatus = "not enrolled"
	default:
		enrollStatus = "not enrolled"
	}

	return deviceJSON{
		ID:           d.Id,
		AssetTag:     d.AssetTag,
		OSType:       osType,
		EnrollStatus: enrollStatus,
		Owner:        d.Owner,
	}
}
