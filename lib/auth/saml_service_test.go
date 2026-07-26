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

// SAML-OSS fork: tests for saml_service.go, the fork's OSS implementation of the
// SAML auth service. Upstream gates SAML behind Enterprise, so there is no
// upstream test coverage for any of this.

package auth_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authtest"
	authority "github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/events/eventstest"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/services"
)

type samlServiceContext struct {
	a           *auth.Server
	b           backend.Backend
	mockEmitter *eventstest.MockRecorderEmitter
}

func setupSAMLServiceContext(t *testing.T) *samlServiceContext {
	t.Helper()

	var tt samlServiceContext

	clock := clockwork.NewFakeClockAt(time.Now())

	b, err := memory.New(memory.Config{
		Context: context.Background(),
		Clock:   clock,
	})
	require.NoError(t, err)
	tt.b = b

	clusterName, err := services.NewClusterNameWithRandomID(types.ClusterNameSpecV2{
		ClusterName: "me.localhost",
	})
	require.NoError(t, err)

	keygen, err := authority.NewKeygen(modules.BuildOSS, clock.Now)
	require.NoError(t, err)

	tt.a, err = auth.NewServer(&auth.InitConfig{
		ClusterName:            clusterName,
		Backend:                b,
		VersionStorage:         authtest.NewFakeTeleportVersion(),
		Authority:              keygen,
		SkipPeriodicOperations: true,
		HostUUID:               uuid.NewString(),
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, trace.NewAggregate(tt.a.Close(), tt.b.Close()))
	})

	tt.mockEmitter = &eventstest.MockRecorderEmitter{}
	tt.a.SetEmitter(tt.mockEmitter)

	return &tt
}

// lastUserLogin returns the most recent emitted event, asserting it is a
// UserLogin.
func lastUserLogin(t *testing.T, emitter *eventstest.MockRecorderEmitter) *apievents.UserLogin {
	t.Helper()
	last := emitter.LastEvent()
	require.NotNil(t, last, "no audit event was emitted")
	require.Equal(t, events.UserLoginEvent, last.GetType())
	login, ok := last.(*apievents.UserLogin)
	require.True(t, ok, "expected *apievents.UserLogin, got %T", last)
	return login
}

// TestValidateSAMLResponse_auditUsesForwardedClientIP pins the fix in commit
// cda6ee3. The proxy's ACS handler forwards the browser's real IP as the clientIP
// argument. authz.ConnectionMetadata(ctx) only sees the internal proxy->auth
// connection, so without the override every SAML login was recorded in the audit
// log as originating from localhost, making the events useless for tracing who
// actually logged in from where.
func TestValidateSAMLResponse_auditUsesForwardedClientIP(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tt := setupSAMLServiceContext(t)

	const clientIP = "203.0.113.9"

	// A malformed response is enough: the audit event is emitted on the failure
	// path too, and the IP handling is identical for success and failure.
	_, err := tt.a.ValidateSAMLResponse(ctx, "not-null-byte-separated", "my-connector", clientIP)
	require.Error(t, err)

	login := lastUserLogin(t, tt.mockEmitter)
	assert.Equal(t, clientIP, login.ConnectionMetadata.RemoteAddr,
		"audit event must record the IP forwarded by the proxy, not the proxy->auth address")
	assert.Equal(t, events.LoginMethodSAML, login.Method)
	assert.False(t, login.Status.Success)
	assert.Equal(t, events.UserSSOLoginFailureCode, login.GetCode())
}

// TestValidateSAMLResponse_emptyClientIPDoesNotClobber checks the guard around
// the override: when the proxy supplies no IP, whatever ConnectionMetadata
// derived from the context must be left alone rather than overwritten with "".
func TestValidateSAMLResponse_emptyClientIPDoesNotClobber(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tt := setupSAMLServiceContext(t)

	// Put a known remote address on the context so an unconditional override
	// would be visible as data loss.
	ctxAddr := "198.51.100.7:4242"
	ctx = authz.ContextWithClientSrcAddr(ctx, &net.TCPAddr{
		IP:   net.ParseIP("198.51.100.7"),
		Port: 4242,
	})

	_, err := tt.a.ValidateSAMLResponse(ctx, "malformed", "my-connector", "")
	require.Error(t, err)

	login := lastUserLogin(t, tt.mockEmitter)
	assert.Equal(t, ctxAddr, login.ConnectionMetadata.RemoteAddr,
		"an empty clientIP must not overwrite the address derived from the context")
}

func TestValidateSAMLResponse_rejectsMalformedEncoding(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tt := setupSAMLServiceContext(t)

	// The proxy joins the RelayState (request ID) and the raw SAML response with
	// a NUL byte. Anything else must be rejected before it reaches the SAML
	// library.
	_, err := tt.a.ValidateSAMLResponse(ctx, "missing-separator", "my-connector", "203.0.113.9")
	require.Error(t, err)
	assert.True(t, trace.IsBadParameter(err), "expected BadParameter, got %v", err)
	assert.Contains(t, err.Error(), "invalid SAML response encoding")

	// A failure must still be audited; a silent rejection would hide probing.
	login := lastUserLogin(t, tt.mockEmitter)
	assert.Equal(t, events.UserSSOLoginFailureCode, login.GetCode())
}

func TestValidateSAMLResponse_unknownConnector(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tt := setupSAMLServiceContext(t)

	// Well-formed encoding, but no such connector exists.
	_, err := tt.a.ValidateSAMLResponse(ctx, "request-id\x00<samlp:Response/>", "no-such-connector", "203.0.113.9")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connector")

	login := lastUserLogin(t, tt.mockEmitter)
	assert.Equal(t, events.UserSSOLoginFailureCode, login.GetCode())
	assert.Equal(t, "203.0.113.9", login.ConnectionMetadata.RemoteAddr)
}

func TestCreateSAMLAuthRequest_unknownConnector(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tt := setupSAMLServiceContext(t)

	_, err := tt.a.CreateSAMLAuthRequest(ctx, types.SAMLAuthRequest{
		ConnectorID:      "no-such-connector",
		CreateWebSession: true,
	})
	require.Error(t, err)
	assert.True(t, trace.IsNotFound(err), "expected NotFound, got %v", err)
}
