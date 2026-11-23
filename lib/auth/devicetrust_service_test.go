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

// SAML-OSS fork: tests for devicetrust_service.go, the fork's OSS device trust
// service. Upstream gates device trust behind Enterprise, so none of this is
// covered upstream.
//
// Scope: the device store, its validation, RBAC, enrollment tokens
// (including auto-enroll), audit events and the SSH key challenge. The TPM
// ceremonies run against a software TPM in devicetrust_tpm_simulator_test.go
// (build tag tpmsimulator). The macOS ceremonies need a Secure Enclave and are
// not exercised here.

package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gravitational/teleport/api/constants"
	devicepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/devicetrust/challenge"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/events/eventstest"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
)

// deviceAdminVerbs are the device verbs of the preset editor/device-admin roles.
var deviceAdminVerbs = []string{
	types.VerbList, types.VerbCreate, types.VerbRead, types.VerbUpdate, types.VerbDelete,
	types.VerbCreateEnrollToken, types.VerbEnroll,
}

// userCtx builds an authz.Context for a local user whose roles allow verbs on
// the "device" kind.
func userCtx(t *testing.T, name string, verbs ...string) *authz.Context {
	t.Helper()
	spec := types.RoleSpecV6{}
	if len(verbs) > 0 {
		spec.Allow.Rules = []types.Rule{{Resources: []string{types.KindDevice}, Verbs: verbs}}
	}
	role, err := types.NewRole("role-"+name, spec)
	require.NoError(t, err)
	user, err := types.NewUser(name)
	require.NoError(t, err)
	user.AddRole(role.GetName())
	checker := services.NewAccessCheckerWithRoleSet(
		&services.AccessInfo{Username: name, Roles: []string{role.GetName()}},
		"localhost", services.NewRoleSet(role))
	identity := authz.LocalUser{Username: name, Identity: tlsca.Identity{Username: name, Groups: []string{role.GetName()}}}
	return &authz.Context{User: user, Checker: checker, Identity: identity, UnmappedIdentity: identity}
}

// asUser makes every RPC on s run as the given authz context.
func asUser(s *ossDeviceTrustService, authCtx *authz.Context) {
	s.authorizer = authz.AuthorizerFunc(func(context.Context) (*authz.Context, error) {
		return authCtx, nil
	})
}

func setDeviceTrust(t *testing.T, s *ossDeviceTrustService, dt *types.DeviceTrust) {
	t.Helper()
	pref, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{DeviceTrust: dt})
	require.NoError(t, err)
	s.getAuthPreference = func(context.Context) (types.AuthPreference, error) { return pref, nil }
}

// newTestDeviceTrustService returns a service whose caller is a device admin.
func newTestDeviceTrustService(t *testing.T) *ossDeviceTrustService {
	t.Helper()
	b, err := memory.New(memory.Config{Context: context.Background()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	s := newOSSDeviceTrustService(b, nil, nil)
	asUser(s, userCtx(t, "admin", deviceAdminVerbs...))
	return s
}

func macOSDevice(assetTag string) *devicepb.Device {
	return &devicepb.Device{
		OsType:   devicepb.OSType_OS_TYPE_MACOS,
		AssetTag: assetTag,
	}
}

func TestDeviceTrustService_CreateDevice_validation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)

	for _, tc := range []struct {
		name string
		req  *devicepb.CreateDeviceRequest
	}{
		{
			name: "nil device",
			req:  &devicepb.CreateDeviceRequest{},
		},
		{
			name: "unspecified OS type",
			req:  &devicepb.CreateDeviceRequest{Device: &devicepb.Device{AssetTag: "tag-1"}},
		},
		{
			// Without an asset tag a device cannot be identified by an operator,
			// and FindDevices by tag would match every such device.
			name: "missing asset tag",
			req:  &devicepb.CreateDeviceRequest{Device: &devicepb.Device{OsType: devicepb.OSType_OS_TYPE_MACOS}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.CreateDevice(ctx, tc.req)
			require.Error(t, err)
			assert.True(t, trace.IsBadParameter(err), "expected BadParameter, got %v", err)
		})
	}
}

func TestDeviceTrustService_CreateDevice(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)

	dev := macOSDevice("laptop-1")
	dev.Owner = "alice"

	created, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: dev})
	require.NoError(t, err)

	assert.NotEmpty(t, created.Id, "server must assign an ID")
	assert.Equal(t, "v1", created.ApiVersion)
	assert.Equal(t, "laptop-1", created.AssetTag)
	assert.Equal(t, "alice", created.Owner, "a caller-supplied owner must be preserved")
	assert.NotNil(t, created.CreateTime)
	assert.NotNil(t, created.UpdateTime)
	// A freshly registered device has not completed the enrollment ceremony, so
	// it must not count as a trusted device yet.
	assert.Equal(t, devicepb.DeviceEnrollStatus_DEVICE_ENROLL_STATUS_NOT_ENROLLED, created.EnrollStatus)

	stored, err := s.GetDevice(ctx, &devicepb.GetDeviceRequest{DeviceId: created.Id})
	require.NoError(t, err)
	assert.Equal(t, created.Id, stored.Id)
	assert.Equal(t, "laptop-1", stored.AssetTag)
}

func TestDeviceTrustService_CreateDevice_enrollToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)

	created, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{
		Device:            macOSDevice("laptop-1"),
		CreateEnrollToken: true,
	})
	require.NoError(t, err)
	require.NotNil(t, created.EnrollToken, "an enroll token was requested")
	assert.NotEmpty(t, created.EnrollToken.Token)

	assert.NotNil(t, created.EnrollToken.ExpireTime, "the token must report its expiry")

	// The token is a one-time enrollment secret; it must not be written to the
	// stored device, or reading a device would leak it.
	stored, err := s.GetDevice(ctx, &devicepb.GetDeviceRequest{DeviceId: created.Id})
	require.NoError(t, err)
	assert.Nil(t, stored.EnrollToken, "the enroll token must not be persisted on the device")
}

func TestDeviceTrustService_GetDevice_notFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)

	_, err := s.GetDevice(ctx, &devicepb.GetDeviceRequest{DeviceId: "no-such-device"})
	require.Error(t, err)
	assert.True(t, trace.IsNotFound(err), "expected NotFound, got %v", err)
}

func TestDeviceTrustService_UpdateDevice(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)

	dev := macOSDevice("laptop-1")
	dev.Owner = "alice"
	created, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: dev})
	require.NoError(t, err)

	t.Run("requires an ID", func(t *testing.T) {
		_, err := s.UpdateDevice(ctx, &devicepb.UpdateDeviceRequest{
			Device: &devicepb.Device{AssetTag: "laptop-2"},
		})
		require.Error(t, err)
		assert.True(t, trace.IsBadParameter(err), "expected BadParameter, got %v", err)
	})

	t.Run("updates supplied fields", func(t *testing.T) {
		updated, err := s.UpdateDevice(ctx, &devicepb.UpdateDeviceRequest{
			Device: &devicepb.Device{Id: created.Id, AssetTag: "laptop-renamed", Owner: "bob"},
		})
		require.NoError(t, err)
		assert.Equal(t, "laptop-renamed", updated.AssetTag)
		assert.Equal(t, "bob", updated.Owner)
	})

	t.Run("empty fields do not clear existing values", func(t *testing.T) {
		// Update is a partial patch: the callers (web UI and tctl) send only the
		// fields they mean to change. An unconditional assignment would blank the
		// owner and asset tag, and a device with no owner drops out of the
		// per-user device lists.
		updated, err := s.UpdateDevice(ctx, &devicepb.UpdateDeviceRequest{
			Device: &devicepb.Device{Id: created.Id},
		})
		require.NoError(t, err)
		assert.Equal(t, "laptop-renamed", updated.AssetTag, "empty asset tag must not clear the stored one")
		assert.Equal(t, "bob", updated.Owner, "empty owner must not clear the stored one")
	})

	t.Run("unknown device", func(t *testing.T) {
		_, err := s.UpdateDevice(ctx, &devicepb.UpdateDeviceRequest{
			Device: &devicepb.Device{Id: "no-such-device", AssetTag: "x"},
		})
		require.Error(t, err)
		assert.True(t, trace.IsNotFound(err), "expected NotFound, got %v", err)
	})
}

func TestDeviceTrustService_UpsertDevice(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)

	t.Run("requires a device", func(t *testing.T) {
		_, err := s.UpsertDevice(ctx, &devicepb.UpsertDeviceRequest{})
		require.Error(t, err)
		assert.True(t, trace.IsBadParameter(err), "expected BadParameter, got %v", err)
	})

	t.Run("creates when absent", func(t *testing.T) {
		created, err := s.UpsertDevice(ctx, &devicepb.UpsertDeviceRequest{Device: macOSDevice("laptop-1")})
		require.NoError(t, err)
		assert.NotEmpty(t, created.Id, "an ID must be assigned when none is supplied")
		assert.Equal(t, "v1", created.ApiVersion)
		require.NotNil(t, created.CreateTime)
		require.NotNil(t, created.UpdateTime)

		stored, err := s.GetDevice(ctx, &devicepb.GetDeviceRequest{DeviceId: created.Id})
		require.NoError(t, err)
		assert.Equal(t, "laptop-1", stored.AssetTag)
	})

	t.Run("overwrites when present", func(t *testing.T) {
		first, err := s.UpsertDevice(ctx, &devicepb.UpsertDeviceRequest{Device: macOSDevice("laptop-2")})
		require.NoError(t, err)

		replacement := macOSDevice("laptop-2-renamed")
		replacement.Id = first.Id
		_, err = s.UpsertDevice(ctx, &devicepb.UpsertDeviceRequest{Device: replacement})
		require.NoError(t, err)

		stored, err := s.GetDevice(ctx, &devicepb.GetDeviceRequest{DeviceId: first.Id})
		require.NoError(t, err)
		assert.Equal(t, "laptop-2-renamed", stored.AssetTag)
	})
}

func TestDeviceTrustService_DeleteDevice(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)

	created, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1")})
	require.NoError(t, err)

	_, err = s.DeleteDevice(ctx, &devicepb.DeleteDeviceRequest{DeviceId: created.Id})
	require.NoError(t, err)

	// Deletion must actually revoke trust, not just return OK.
	_, err = s.GetDevice(ctx, &devicepb.GetDeviceRequest{DeviceId: created.Id})
	require.Error(t, err)
	assert.True(t, trace.IsNotFound(err), "device must be gone after delete, got %v", err)

	_, err = s.DeleteDevice(ctx, &devicepb.DeleteDeviceRequest{DeviceId: created.Id})
	assert.Error(t, err, "deleting an absent device must not report success")
}

func TestDeviceTrustService_ListDevices(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)

	resp, err := s.ListDevices(ctx, &devicepb.ListDevicesRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.Devices)

	want := []string{"laptop-1", "laptop-2", "laptop-3"}
	for _, tag := range want {
		_, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice(tag)})
		require.NoError(t, err)
	}

	resp, err = s.ListDevices(ctx, &devicepb.ListDevicesRequest{})
	require.NoError(t, err)

	got := make([]string, 0, len(resp.Devices))
	for _, d := range resp.Devices {
		got = append(got, d.AssetTag)
	}
	assert.ElementsMatch(t, want, got)
}

func TestDeviceTrustService_FindDevices(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)

	first, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("shared-tag")})
	require.NoError(t, err)
	// CreateDevice rejects duplicates, so seed a legacy duplicate directly.
	_, err = s.UpsertDevice(ctx, &devicepb.UpsertDeviceRequest{Device: macOSDevice("shared-tag")})
	require.NoError(t, err)
	_, err = s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("unique-tag")})
	require.NoError(t, err)

	t.Run("requires a query", func(t *testing.T) {
		_, err := s.FindDevices(ctx, &devicepb.FindDevicesRequest{})
		require.Error(t, err)
		assert.True(t, trace.IsBadParameter(err), "expected BadParameter, got %v", err)
	})

	t.Run("by device ID", func(t *testing.T) {
		// An ID is unique, so it must resolve to exactly one device even though
		// its asset tag is shared with another.
		resp, err := s.FindDevices(ctx, &devicepb.FindDevicesRequest{IdOrTag: first.Id})
		require.NoError(t, err)
		require.Len(t, resp.Devices, 1)
		assert.Equal(t, first.Id, resp.Devices[0].Id)
	})

	t.Run("by asset tag returns every match", func(t *testing.T) {
		// Asset tags are not unique. Returning only the first would hide a
		// duplicate-tag misconfiguration from the operator.
		resp, err := s.FindDevices(ctx, &devicepb.FindDevicesRequest{IdOrTag: "shared-tag"})
		require.NoError(t, err)
		assert.Len(t, resp.Devices, 2)
	})

	t.Run("no match", func(t *testing.T) {
		resp, err := s.FindDevices(ctx, &devicepb.FindDevicesRequest{IdOrTag: "nope"})
		require.NoError(t, err, "a miss is not an error")
		assert.Empty(t, resp.Devices)
	})
}

func TestDeviceTrustService_CreateDeviceEnrollToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)

	created, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1")})
	require.NoError(t, err)

	token, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{
		DeviceId: created.Id,
	})
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.NotEmpty(t, token.Token)

	// Re-issuing must produce a distinct secret rather than replaying the old
	// one, so a leaked token cannot be reused after rotation.
	second, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{
		DeviceId: created.Id,
	})
	require.NoError(t, err)
	assert.NotEqual(t, token.Token, second.Token)
}

func newTestDeviceTrustServiceWithClock(t *testing.T) (*ossDeviceTrustService, *clockwork.FakeClock) {
	t.Helper()
	clock := clockwork.NewFakeClock()
	b, err := memory.New(memory.Config{Context: context.Background(), Clock: clock})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	s := newOSSDeviceTrustService(b, nil, nil)
	s.clock = clock
	asUser(s, userCtx(t, "admin", deviceAdminVerbs...))
	return s, clock
}

func macOSData(serial string) *devicepb.DeviceCollectedData {
	return &devicepb.DeviceCollectedData{OsType: devicepb.OSType_OS_TYPE_MACOS, SerialNumber: serial}
}

func TestDeviceTrustService_CreateDevice_rejectsDuplicates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)

	_, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1")})
	require.NoError(t, err)
	// Enrollment looks devices up by OS and serial, so a duplicate would make
	// the enrolled record arbitrary.
	_, err = s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1")})
	require.Error(t, err)
	assert.True(t, trace.IsAlreadyExists(err), "expected AlreadyExists, got %v", err)
}

func TestDeviceTrustService_RBAC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)

	dev, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1")})
	require.NoError(t, err)

	// A user without device rules must not touch the inventory.
	asUser(s, userCtx(t, "mallory"))

	calls := map[string]func() error{
		"CreateDevice": func() error {
			_, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-2")})
			return err
		},
		"UpdateDevice": func() error {
			_, err := s.UpdateDevice(ctx, &devicepb.UpdateDeviceRequest{Device: &devicepb.Device{Id: dev.Id, Owner: "mallory"}})
			return err
		},
		"UpsertDevice": func() error {
			_, err := s.UpsertDevice(ctx, &devicepb.UpsertDeviceRequest{Device: macOSDevice("laptop-3")})
			return err
		},
		"DeleteDevice": func() error {
			_, err := s.DeleteDevice(ctx, &devicepb.DeleteDeviceRequest{DeviceId: dev.Id})
			return err
		},
		"GetDevice": func() error {
			_, err := s.GetDevice(ctx, &devicepb.GetDeviceRequest{DeviceId: dev.Id})
			return err
		},
		"ListDevices": func() error {
			_, err := s.ListDevices(ctx, &devicepb.ListDevicesRequest{})
			return err
		},
		"FindDevices": func() error {
			_, err := s.FindDevices(ctx, &devicepb.FindDevicesRequest{IdOrTag: "laptop-1"})
			return err
		},
		"CreateDeviceEnrollToken by ID": func() error {
			_, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceId: dev.Id})
			return err
		},
	}
	for name, call := range calls {
		err := call()
		require.Error(t, err, name)
		assert.True(t, trace.IsAccessDenied(err), "%s: expected AccessDenied, got %v", name, err)
	}

	// Read-only rules allow reads but not writes.
	asUser(s, userCtx(t, "auditor", types.VerbList, types.VerbRead))
	_, err = s.ListDevices(ctx, &devicepb.ListDevicesRequest{})
	require.NoError(t, err)
	_, err = s.DeleteDevice(ctx, &devicepb.DeleteDeviceRequest{DeviceId: dev.Id})
	assert.True(t, trace.IsAccessDenied(err), "expected AccessDenied, got %v", err)

	// A service without an authorizer refuses everything.
	s.authorizer = nil
	_, err = s.ListDevices(ctx, &devicepb.ListDevicesRequest{})
	assert.True(t, trace.IsAccessDenied(err), "expected AccessDenied, got %v", err)
}

func TestDeviceTrustService_AutoEnrollToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	setup := func(t *testing.T, dt *types.DeviceTrust) *ossDeviceTrustService {
		s := newTestDeviceTrustService(t)
		_, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("SERIAL1")})
		require.NoError(t, err)
		setDeviceTrust(t, s, dt)
		asUser(s, userCtx(t, "alice")) // no device rules at all
		return s
	}
	autoOn := &types.DeviceTrust{Mode: constants.DeviceTrustModeOptional, AutoEnroll: true}

	t.Run("allowed for a registered, unenrolled device", func(t *testing.T) {
		s := setup(t, autoOn)
		tok, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceData: macOSData("SERIAL1")})
		require.NoError(t, err)
		assert.NotEmpty(t, tok.Token)
		assert.NotNil(t, tok.ExpireTime)
	})

	t.Run("denied when auto_enroll is off", func(t *testing.T) {
		s := setup(t, &types.DeviceTrust{Mode: constants.DeviceTrustModeOptional})
		_, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceData: macOSData("SERIAL1")})
		assert.True(t, trace.IsAccessDenied(err), "expected AccessDenied, got %v", err)
	})

	t.Run("denied when device trust is off", func(t *testing.T) {
		s := setup(t, &types.DeviceTrust{Mode: constants.DeviceTrustModeOff, AutoEnroll: true})
		_, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceData: macOSData("SERIAL1")})
		assert.True(t, trace.IsAccessDenied(err), "expected AccessDenied, got %v", err)
	})

	t.Run("denied for an unregistered device", func(t *testing.T) {
		s := setup(t, autoOn)
		_, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceData: macOSData("UNKNOWN")})
		assert.True(t, trace.IsAccessDenied(err), "expected AccessDenied, got %v", err)
	})

	t.Run("denied for an OS mismatch", func(t *testing.T) {
		s := setup(t, autoOn)
		_, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{
			DeviceData: &devicepb.DeviceCollectedData{OsType: devicepb.OSType_OS_TYPE_WINDOWS, SerialNumber: "SERIAL1"},
		})
		assert.True(t, trace.IsAccessDenied(err), "expected AccessDenied, got %v", err)
	})

	t.Run("denied for an enrolled device", func(t *testing.T) {
		s := setup(t, autoOn)
		// Auto-enroll must not let any user replace the credential of an
		// already trusted device.
		dev, err := s.findDeviceByOSTag(ctx, devicepb.OSType_OS_TYPE_MACOS, "SERIAL1")
		require.NoError(t, err)
		dev.EnrollStatus = devicepb.DeviceEnrollStatus_DEVICE_ENROLL_STATUS_ENROLLED
		require.NoError(t, s.putDevice(ctx, dev))

		_, err = s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceData: macOSData("SERIAL1")})
		assert.True(t, trace.IsAccessDenied(err), "expected AccessDenied, got %v", err)
	})

	t.Run("denied for non-user identities", func(t *testing.T) {
		s := setup(t, autoOn)
		svc := userCtx(t, "proxy")
		svc.UnmappedIdentity = authz.BuiltinRole{Role: types.RoleProxy, Username: "proxy"}
		asUser(s, svc)
		_, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceData: macOSData("SERIAL1")})
		assert.True(t, trace.IsAccessDenied(err), "expected AccessDenied, got %v", err)
	})

	t.Run("admins may use device data without auto_enroll", func(t *testing.T) {
		s := setup(t, &types.DeviceTrust{Mode: constants.DeviceTrustModeOptional})
		asUser(s, userCtx(t, "admin", deviceAdminVerbs...))
		_, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceData: macOSData("SERIAL1")})
		require.NoError(t, err)
	})

	t.Run("requires device ID or data", func(t *testing.T) {
		s := setup(t, autoOn)
		_, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{})
		assert.True(t, trace.IsBadParameter(err), "expected BadParameter, got %v", err)
	})
}

func TestDeviceTrustService_EnrollTokens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("single use", func(t *testing.T) {
		s, _ := newTestDeviceTrustServiceWithClock(t)
		dev, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1")})
		require.NoError(t, err)
		tok, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceId: dev.Id})
		require.NoError(t, err)

		require.Error(t, s.spendEnrollToken(ctx, dev.Id, "wrong"))
		require.NoError(t, s.spendEnrollToken(ctx, dev.Id, tok.Token))
		err = s.spendEnrollToken(ctx, dev.Id, tok.Token)
		assert.True(t, trace.IsAccessDenied(err), "a spent token must not work again, got %v", err)
	})

	t.Run("only the hash is stored", func(t *testing.T) {
		s, _ := newTestDeviceTrustServiceWithClock(t)
		dev, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1")})
		require.NoError(t, err)
		tok, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceId: dev.Id})
		require.NoError(t, err)
		item, err := s.backend.Get(ctx, enrollTokenKey(dev.Id))
		require.NoError(t, err)
		assert.NotContains(t, string(item.Value), tok.Token)
	})

	t.Run("reissue invalidates the previous token", func(t *testing.T) {
		s, _ := newTestDeviceTrustServiceWithClock(t)
		dev, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1")})
		require.NoError(t, err)
		first, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceId: dev.Id})
		require.NoError(t, err)
		second, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceId: dev.Id})
		require.NoError(t, err)
		require.Error(t, s.spendEnrollToken(ctx, dev.Id, first.Token))
		require.NoError(t, s.spendEnrollToken(ctx, dev.Id, second.Token))
	})

	t.Run("expires", func(t *testing.T) {
		s, clock := newTestDeviceTrustServiceWithClock(t)
		dev, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1")})
		require.NoError(t, err)
		tok, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{DeviceId: dev.Id})
		require.NoError(t, err)
		assert.WithinDuration(t, clock.Now().Add(defaultEnrollTokenTTL), tok.ExpireTime.AsTime(), 0)

		clock.Advance(defaultEnrollTokenTTL + time.Second)
		err = s.spendEnrollToken(ctx, dev.Id, tok.Token)
		assert.True(t, trace.IsAccessDenied(err), "an expired token must not work, got %v", err)
	})

	t.Run("requested expiry is honored and capped", func(t *testing.T) {
		s, clock := newTestDeviceTrustServiceWithClock(t)
		dev, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1")})
		require.NoError(t, err)

		want := clock.Now().Add(2 * time.Hour)
		tok, err := s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{
			DeviceId: dev.Id, ExpireTime: timestamppb.New(want),
		})
		require.NoError(t, err)
		assert.WithinDuration(t, want, tok.ExpireTime.AsTime(), 0)

		tok, err = s.CreateDeviceEnrollToken(ctx, &devicepb.CreateDeviceEnrollTokenRequest{
			DeviceId: dev.Id, ExpireTime: timestamppb.New(clock.Now().Add(365 * 24 * time.Hour)),
		})
		require.NoError(t, err)
		assert.WithinDuration(t, clock.Now().Add(maxEnrollTokenTTL), tok.ExpireTime.AsTime(), 0)
	})

	t.Run("deleting the device deletes its token", func(t *testing.T) {
		s, _ := newTestDeviceTrustServiceWithClock(t)
		dev, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1"), CreateEnrollToken: true})
		require.NoError(t, err)
		_, err = s.DeleteDevice(ctx, &devicepb.DeleteDeviceRequest{DeviceId: dev.Id})
		require.NoError(t, err)
		_, err = s.backend.Get(ctx, enrollTokenKey(dev.Id))
		assert.True(t, trace.IsNotFound(err), "expected NotFound, got %v", err)
	})

	t.Run("tokens do not show up as devices", func(t *testing.T) {
		s, _ := newTestDeviceTrustServiceWithClock(t)
		_, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1"), CreateEnrollToken: true})
		require.NoError(t, err)
		resp, err := s.ListDevices(ctx, &devicepb.ListDevicesRequest{})
		require.NoError(t, err)
		assert.Len(t, resp.Devices, 1)
	})
}

func TestDeviceTrustService_AuditEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newTestDeviceTrustService(t)
	emitter := &eventstest.MockRecorderEmitter{}
	s.emitter = emitter

	dev, err := s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("laptop-1"), CreateEnrollToken: true})
	require.NoError(t, err)
	_, err = s.UpdateDevice(ctx, &devicepb.UpdateDeviceRequest{Device: &devicepb.Device{Id: dev.Id, Owner: "bob"}})
	require.NoError(t, err)
	_, err = s.DeleteDevice(ctx, &devicepb.DeleteDeviceRequest{DeviceId: dev.Id})
	require.NoError(t, err)

	var got []string
	for _, ev := range emitter.Events() {
		de, ok := ev.(*apievents.DeviceEvent2)
		require.True(t, ok, "unexpected event type %T", ev)
		assert.Equal(t, "laptop-1", de.Device.AssetTag)
		assert.True(t, de.Status.Success)
		got = append(got, de.Metadata.Code)
	}
	assert.Equal(t, []string{
		events.DeviceCreateCode,
		events.DeviceEnrollTokenCreateCode,
		events.DeviceUpdateCode,
		events.DeviceDeleteCode,
	}, got)
}

func TestVerifySSHKeyChallenge(t *testing.T) {
	t.Parallel()

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	require.NoError(t, err)
	userPub, userPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshUserPub, err := ssh.NewPublicKey(userPub)
	require.NoError(t, err)
	cert := &ssh.Certificate{Key: sshUserPub, CertType: ssh.UserCert, KeyId: "llama", ValidBefore: ssh.CertTimeInfinity}
	require.NoError(t, cert.SignCert(rand.Reader, caSigner))
	authorizedKey := ssh.MarshalAuthorizedKey(cert)

	chal, err := challenge.New()
	require.NoError(t, err)
	goodSig := ed25519.Sign(userPriv, chal)
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verified, err := verifySSHKeyChallenge(authorizedKey, chal, goodSig)
	require.NoError(t, err)
	assert.True(t, verified)

	// No signature: not verified, the TLS/SSH key match check applies.
	verified, err = verifySSHKeyChallenge(authorizedKey, chal, nil)
	require.NoError(t, err)
	assert.False(t, verified)

	// Signed by another key, or over another challenge.
	_, err = verifySSHKeyChallenge(authorizedKey, chal, ed25519.Sign(otherPriv, chal))
	assert.True(t, trace.IsAccessDenied(err), "got %v", err)
	_, err = verifySSHKeyChallenge(authorizedKey, []byte("another challenge"), goodSig)
	assert.True(t, trace.IsAccessDenied(err), "got %v", err)

	// Garbage key.
	_, err = verifySSHKeyChallenge([]byte("not a key"), chal, goodSig)
	assert.Error(t, err)
}
