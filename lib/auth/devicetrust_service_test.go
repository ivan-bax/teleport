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
// Scope: the device store and its validation. The enrollment and authentication
// ceremonies (enrollMacOS, enrollTPM, authenticateMacOS, authenticateTPM) need
// real Secure Enclave / TPM attestation and are not exercised here, so the
// EnrollDevice owner assignment is likewise uncovered — see the note on
// TestDeviceTrustService_UpdateDevice for the owner behaviour that is covered.

package auth

import (
	"context"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	devicepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1"
	"github.com/gravitational/teleport/lib/backend/memory"
)

func newTestDeviceTrustService(t *testing.T) *ossDeviceTrustService {
	t.Helper()
	b, err := memory.New(memory.Config{Context: context.Background()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	// The CRUD surface only touches the backend; authServer and authorizer are
	// exercised by the enrollment ceremonies, which are out of scope here.
	return newOSSDeviceTrustService(b, nil, nil)
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

	// The token is a one-time enrollment secret held in memory; it must not be
	// written to the stored device, or reading a device would leak it.
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
	_, err = s.CreateDevice(ctx, &devicepb.CreateDeviceRequest{Device: macOSDevice("shared-tag")})
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
