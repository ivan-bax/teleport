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

package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gravitational/teleport/api/constants"
	devicepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/devicetrust/assertserver"
	"github.com/gravitational/teleport/lib/devicetrust/challenge"
	"github.com/gravitational/teleport/lib/events"
)

const (
	// defaultEnrollTokenTTL is used when the caller doesn't ask for a specific
	// enrollment token expiry.
	defaultEnrollTokenTTL = 30 * time.Minute
	// maxEnrollTokenTTL caps caller-requested enrollment token expiries.
	maxEnrollTokenTTL = 7 * 24 * time.Hour
)

// authnStream is a simple send/recv interface used for device authentication
// and enrollment challenge-response flows.
type authnStream interface {
	Send(*devicepb.AuthenticateDeviceResponse) error
	Recv() (*devicepb.AuthenticateDeviceRequest, error)
}

// ossDeviceTrustService implements DeviceTrustServiceServer for OSS Teleport.
// It provides device CRUD, enrollment, and authentication backed by the
// Teleport backend storage.
//
// Every RPC authorizes the caller. Inventory management (create, update,
// delete, read, list, issuing enroll tokens) requires RBAC rules on the
// "device" kind, same as upstream Enterprise. Enrollment and authentication
// only require an authenticated user: the enroll token, or the device
// credential, is what proves the right to act on the device.
type ossDeviceTrustService struct {
	devicepb.UnimplementedDeviceTrustServiceServer

	backend    backend.Backend
	authServer *Server
	authorizer authz.Authorizer

	// getAuthPreference returns the cluster auth preference (for the
	// device_trust mode and auto_enroll settings).
	getAuthPreference func(context.Context) (types.AuthPreference, error)
	// emitter receives device.* audit events. May be nil (tests).
	emitter apievents.Emitter
	clock   clockwork.Clock

	// mu protects in-memory web auth attempts.
	// Enrollment tokens live in the backend, so they expire, survive auth
	// restarts and are shared between auth replicas.
	mu        sync.Mutex
	webTokens map[string]*webAuthnAttempt
}

type webAuthnAttempt struct {
	expectedDeviceID string
	webSessionID     string
	webToken         string
	confirmToken     string
}

func newOSSDeviceTrustService(b backend.Backend, authServer *Server, authorizer authz.Authorizer) *ossDeviceTrustService {
	s := &ossDeviceTrustService{
		backend:    b,
		authServer: authServer,
		authorizer: authorizer,
		clock:      clockwork.NewRealClock(),
		webTokens:  make(map[string]*webAuthnAttempt),
	}
	if authServer != nil {
		s.getAuthPreference = authServer.GetAuthPreference
		s.emitter = authServer
		s.clock = authServer.GetClock()
	}
	return s
}

func deviceKey(id string) backend.Key {
	return backend.NewKey("devices", "id", id)
}

func enrollTokenKey(deviceID string) backend.Key {
	return backend.NewKey("devices", "enroll_tokens", deviceID)
}

// authorize authenticates the caller and, when verbs are given, checks that
// the caller's roles allow them on the "device" kind.
func (s *ossDeviceTrustService) authorize(ctx context.Context, verbs ...string) (*authz.Context, error) {
	if s.authorizer == nil {
		return nil, trace.AccessDenied("device trust authorizer not configured")
	}
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(verbs) > 0 {
		if err := authCtx.CheckAccessToKind(types.KindDevice, verbs[0], verbs[1:]...); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return authCtx, nil
}

// authorizeUser authenticates the caller and requires it to be a user
// (local or from a trusted cluster), as opposed to a Teleport service.
func (s *ossDeviceTrustService) authorizeUser(ctx context.Context) (*authz.Context, error) {
	authCtx, err := s.authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if !authz.IsLocalOrRemoteUser(*authCtx) {
		return nil, trace.AccessDenied("device enrollment and authentication require a user identity")
	}
	return authCtx, nil
}

// emitDeviceEvent records a device.* audit event. Failures to emit are logged
// by the emitter and never fail the RPC.
func (s *ossDeviceTrustService) emitDeviceEvent(ctx context.Context, eventType, code string, dev *devicepb.Device, user string, opErr error) {
	if s.emitter == nil {
		return
	}
	ev := &apievents.DeviceEvent2{
		Metadata: apievents.Metadata{Type: eventType, Code: code},
		Status:   apievents.Status{Success: opErr == nil},
	}
	if opErr != nil {
		ev.Status.Error = opErr.Error()
	}
	if user != "" {
		ev.UserMetadata = authz.ClientUserMetadataWithUser(ctx, user)
	} else {
		ev.UserMetadata = authz.ClientUserMetadata(ctx)
	}
	if dev != nil {
		ev.Device = &apievents.DeviceMetadata{
			DeviceId: dev.Id,
			OsType:   apievents.OSType(dev.OsType),
			AssetTag: dev.AssetTag,
		}
		if dev.Credential != nil {
			ev.Device.CredentialId = dev.Credential.Id
		}
	}
	_ = s.emitter.EmitAuditEvent(ctx, ev)
}

// enrollTokenTTL picks the expiry for a new enrollment token.
func (s *ossDeviceTrustService) enrollTokenExpiry(requested *timestamppb.Timestamp) time.Time {
	now := s.clock.Now()
	if requested != nil && requested.IsValid() {
		exp := requested.AsTime()
		if exp.After(now) {
			if exp.After(now.Add(maxEnrollTokenTTL)) {
				return now.Add(maxEnrollTokenTTL)
			}
			return exp
		}
	}
	return now.Add(defaultEnrollTokenTTL)
}

func hashEnrollToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// issueEnrollToken creates (or replaces) the enrollment token of a device. Only
// the token hash is stored. The backend item expires with the token.
func (s *ossDeviceTrustService) issueEnrollToken(ctx context.Context, deviceID string, requestedExpiry *timestamppb.Timestamp) (*devicepb.DeviceEnrollToken, error) {
	token := uuid.NewString()
	expires := s.enrollTokenExpiry(requestedExpiry)
	if _, err := s.backend.Put(ctx, backend.Item{
		Key:     enrollTokenKey(deviceID),
		Value:   []byte(hashEnrollToken(token)),
		Expires: expires,
	}); err != nil {
		return nil, trace.Wrap(err)
	}
	return &devicepb.DeviceEnrollToken{
		Token:      token,
		ExpireTime: timestamppb.New(expires),
	}, nil
}

// spendEnrollToken validates and deletes the enrollment token of a device. A
// conditional delete makes sure a token can be spent only once, even across
// auth replicas.
func (s *ossDeviceTrustService) spendEnrollToken(ctx context.Context, deviceID, token string) error {
	invalid := trace.AccessDenied("invalid device enrollment token")
	item, err := s.backend.Get(ctx, enrollTokenKey(deviceID))
	if err != nil {
		if trace.IsNotFound(err) {
			return invalid
		}
		return trace.Wrap(err)
	}
	if !item.Expires.IsZero() && !s.clock.Now().Before(item.Expires) {
		return invalid
	}
	if subtle.ConstantTimeCompare(item.Value, []byte(hashEnrollToken(token))) != 1 {
		return invalid
	}
	if err := s.backend.ConditionalDelete(ctx, enrollTokenKey(deviceID), item.Revision); err != nil {
		if trace.IsNotFound(err) || trace.IsCompareFailed(err) {
			return invalid
		}
		return trace.Wrap(err)
	}
	return nil
}

func (s *ossDeviceTrustService) deleteEnrollToken(ctx context.Context, deviceID string) error {
	if err := s.backend.Delete(ctx, enrollTokenKey(deviceID)); err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	return nil
}

func (s *ossDeviceTrustService) marshalDevice(dev *devicepb.Device) ([]byte, error) {
	data, err := protojson.Marshal(dev)
	return data, trace.Wrap(err)
}

func (s *ossDeviceTrustService) unmarshalDevice(data []byte) (*devicepb.Device, error) {
	dev := &devicepb.Device{}
	if err := protojson.Unmarshal(data, dev); err != nil {
		return nil, trace.Wrap(err)
	}
	return dev, nil
}

func (s *ossDeviceTrustService) getDevice(ctx context.Context, id string) (*devicepb.Device, error) {
	item, err := s.backend.Get(ctx, deviceKey(id))
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("device %q not found", id)
		}
		return nil, trace.Wrap(err)
	}
	return s.unmarshalDevice(item.Value)
}

func (s *ossDeviceTrustService) putDevice(ctx context.Context, dev *devicepb.Device) error {
	data, err := s.marshalDevice(dev)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = s.backend.Put(ctx, backend.Item{
		Key:   deviceKey(dev.Id),
		Value: data,
	})
	return trace.Wrap(err)
}

func (s *ossDeviceTrustService) listAllDevices(ctx context.Context) ([]*devicepb.Device, error) {
	startKey := backend.NewKey("devices", "id")
	result, err := s.backend.GetRange(ctx, startKey, backend.RangeEnd(startKey), 1000)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var devices []*devicepb.Device
	for _, item := range result.Items {
		dev, err := s.unmarshalDevice(item.Value)
		if err != nil {
			continue
		}
		devices = append(devices, dev)
	}
	return devices, nil
}

// CreateDevice registers a new device.
func (s *ossDeviceTrustService) CreateDevice(ctx context.Context, req *devicepb.CreateDeviceRequest) (*devicepb.Device, error) {
	verbs := []string{types.VerbCreate}
	if req.GetCreateEnrollToken() {
		verbs = append(verbs, types.VerbCreateEnrollToken)
	}
	if _, err := s.authorize(ctx, verbs...); err != nil {
		return nil, trace.Wrap(err)
	}

	dev := req.GetDevice()
	switch {
	case dev == nil:
		return nil, trace.BadParameter("device required")
	case dev.OsType == devicepb.OSType_OS_TYPE_UNSPECIFIED:
		return nil, trace.BadParameter("device OS type required")
	case dev.AssetTag == "":
		return nil, trace.BadParameter("device asset tag required")
	}

	now := timestamppb.Now()
	created := &devicepb.Device{
		ApiVersion:   "v1",
		Id:           uuid.NewString(),
		OsType:       dev.OsType,
		AssetTag:     dev.AssetTag,
		CreateTime:   now,
		UpdateTime:   now,
		EnrollStatus: devicepb.DeviceEnrollStatus_DEVICE_ENROLL_STATUS_NOT_ENROLLED,
		Owner:        dev.Owner,
	}

	if existing, err := s.findDeviceByOSTag(ctx, dev.OsType, dev.AssetTag); err == nil {
		return nil, trace.AlreadyExists("device %q/%v already registered (id %s)", dev.AssetTag, dev.OsType, existing.Id)
	} else if !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	if err := s.putDevice(ctx, created); err != nil {
		return nil, trace.Wrap(err)
	}
	s.emitDeviceEvent(ctx, events.DeviceCreateEvent, events.DeviceCreateCode, created, "", nil)

	if req.CreateEnrollToken {
		token, err := s.issueEnrollToken(ctx, created.Id, req.EnrollTokenExpireTime)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		s.emitDeviceEvent(ctx, events.DeviceEnrollTokenCreateEvent, events.DeviceEnrollTokenCreateCode, created, "", nil)

		resp := cloneDevice(created)
		resp.EnrollToken = token
		return resp, nil
	}

	return created, nil
}

// UpdateDevice updates an existing device.
func (s *ossDeviceTrustService) UpdateDevice(ctx context.Context, req *devicepb.UpdateDeviceRequest) (*devicepb.Device, error) {
	if _, err := s.authorize(ctx, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}

	dev := req.GetDevice()
	if dev == nil || dev.Id == "" {
		return nil, trace.BadParameter("device with ID required")
	}

	existing, err := s.getDevice(ctx, dev.Id)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if dev.AssetTag != "" {
		existing.AssetTag = dev.AssetTag
	}
	if dev.Owner != "" {
		existing.Owner = dev.Owner
	}
	existing.UpdateTime = timestamppb.Now()

	if err := s.putDevice(ctx, existing); err != nil {
		return nil, trace.Wrap(err)
	}
	s.emitDeviceEvent(ctx, events.DeviceUpdateEvent, events.DeviceUpdateCode, existing, "", nil)
	return existing, nil
}

// UpsertDevice creates or updates a device.
func (s *ossDeviceTrustService) UpsertDevice(ctx context.Context, req *devicepb.UpsertDeviceRequest) (*devicepb.Device, error) {
	if _, err := s.authorize(ctx, types.VerbCreate, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}

	dev := req.GetDevice()
	if dev == nil {
		return nil, trace.BadParameter("device required")
	}

	if dev.Id == "" {
		dev.Id = uuid.NewString()
	}
	now := timestamppb.Now()
	if dev.CreateTime == nil {
		dev.CreateTime = now
	}
	dev.UpdateTime = now
	if dev.ApiVersion == "" {
		dev.ApiVersion = "v1"
	}

	if err := s.putDevice(ctx, dev); err != nil {
		return nil, trace.Wrap(err)
	}
	s.emitDeviceEvent(ctx, events.DeviceUpdateEvent, events.DeviceUpdateCode, dev, "", nil)
	return dev, nil
}

// DeleteDevice removes a device.
func (s *ossDeviceTrustService) DeleteDevice(ctx context.Context, req *devicepb.DeleteDeviceRequest) (*emptypb.Empty, error) {
	if _, err := s.authorize(ctx, types.VerbDelete); err != nil {
		return nil, trace.Wrap(err)
	}
	if req.DeviceId == "" {
		return nil, trace.BadParameter("device ID required")
	}

	dev, err := s.getDevice(ctx, req.DeviceId)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := s.backend.Delete(ctx, deviceKey(req.DeviceId)); err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("device %q not found", req.DeviceId)
		}
		return nil, trace.Wrap(err)
	}
	if err := s.deleteEnrollToken(ctx, req.DeviceId); err != nil {
		return nil, trace.Wrap(err)
	}
	s.emitDeviceEvent(ctx, events.DeviceDeleteEvent, events.DeviceDeleteCode, dev, "", nil)

	return &emptypb.Empty{}, nil
}

// GetDevice retrieves a device by ID.
func (s *ossDeviceTrustService) GetDevice(ctx context.Context, req *devicepb.GetDeviceRequest) (*devicepb.Device, error) {
	if _, err := s.authorize(ctx, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	if req.DeviceId == "" {
		return nil, trace.BadParameter("device ID required")
	}
	return s.getDevice(ctx, req.DeviceId)
}

// ListDevices lists all devices.
func (s *ossDeviceTrustService) ListDevices(ctx context.Context, req *devicepb.ListDevicesRequest) (*devicepb.ListDevicesResponse, error) {
	if _, err := s.authorize(ctx, types.VerbList, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	devices, err := s.listAllDevices(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &devicepb.ListDevicesResponse{Devices: devices}, nil
}

// FindDevices searches for devices by ID or asset tag.
func (s *ossDeviceTrustService) FindDevices(ctx context.Context, req *devicepb.FindDevicesRequest) (*devicepb.FindDevicesResponse, error) {
	if _, err := s.authorize(ctx, types.VerbList, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	if req.IdOrTag == "" {
		return nil, trace.BadParameter("id_or_tag required")
	}

	// Try direct ID lookup first.
	if dev, err := s.getDevice(ctx, req.IdOrTag); err == nil {
		return &devicepb.FindDevicesResponse{Devices: []*devicepb.Device{dev}}, nil
	}

	// Fall back to scanning by asset tag.
	allDevices, err := s.listAllDevices(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var found []*devicepb.Device
	for _, d := range allDevices {
		if d.AssetTag == req.IdOrTag {
			found = append(found, d)
		}
	}
	return &devicepb.FindDevicesResponse{Devices: found}, nil
}

// CreateDeviceEnrollToken creates an enrollment token for a device.
//
// There are two modes, matching upstream:
//   - Admin: the request names the device by DeviceId (tctl devices enroll,
//     tsh device enroll --current-device). Requires create_enroll_token on the
//     "device" kind.
//   - Auto-enroll: the request carries only DeviceData (tsh login / Teleport
//     Connect after a failed device authentication). Allowed for any user when
//     the cluster has device_trust.auto_enroll enabled, the device is
//     registered and it is not enrolled yet. Callers with create_enroll_token
//     may also use DeviceData without auto_enroll.
func (s *ossDeviceTrustService) CreateDeviceEnrollToken(ctx context.Context, req *devicepb.CreateDeviceEnrollTokenRequest) (*devicepb.DeviceEnrollToken, error) {
	authCtx, err := s.authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	isAdmin := authCtx.CheckAccessToKind(types.KindDevice, types.VerbCreateEnrollToken) == nil

	var dev *devicepb.Device
	switch {
	case req.DeviceId != "":
		if !isAdmin {
			return nil, trace.AccessDenied("access denied to perform action %q on %q", types.VerbCreateEnrollToken, types.KindDevice)
		}
		if dev, err = s.getDevice(ctx, req.DeviceId); err != nil {
			return nil, trace.Wrap(err)
		}

	case req.DeviceData != nil:
		if err := validateDeviceData(req.DeviceData); err != nil {
			return nil, trace.Wrap(err)
		}
		if !isAdmin {
			if err := s.checkAutoEnrollAllowed(ctx, authCtx); err != nil {
				return nil, trace.Wrap(err)
			}
		}
		dev, err = s.findDeviceByOSTag(ctx, req.DeviceData.OsType, req.DeviceData.SerialNumber)
		if trace.IsNotFound(err) {
			return nil, trace.AccessDenied("device %q is not registered in the device inventory", req.DeviceData.SerialNumber)
		} else if err != nil {
			return nil, trace.Wrap(err)
		}
		if !isAdmin && dev.EnrollStatus == devicepb.DeviceEnrollStatus_DEVICE_ENROLL_STATUS_ENROLLED {
			return nil, trace.AccessDenied("device %q is already enrolled", dev.AssetTag)
		}

	default:
		return nil, trace.BadParameter("device ID or device data required")
	}

	token, err := s.issueEnrollToken(ctx, dev.Id, req.ExpireTime)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.emitDeviceEvent(ctx, events.DeviceEnrollTokenCreateEvent, events.DeviceEnrollTokenCreateCode, dev, "", nil)
	return token, nil
}

// checkAutoEnrollAllowed verifies that the cluster allows auto-enrollment and
// that the caller is a user.
func (s *ossDeviceTrustService) checkAutoEnrollAllowed(ctx context.Context, authCtx *authz.Context) error {
	if !authz.IsLocalOrRemoteUser(*authCtx) {
		return trace.AccessDenied("device auto-enrollment requires a user identity")
	}
	if s.getAuthPreference == nil {
		return trace.AccessDenied("device auto-enrollment not available")
	}
	pref, err := s.getAuthPreference(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	dt := pref.GetDeviceTrust()
	if dt == nil || !dt.AutoEnroll || dt.Mode == constants.DeviceTrustModeOff {
		return trace.AccessDenied("device auto-enrollment is disabled")
	}
	return nil
}

// EnrollDevice implements the server-side device enrollment ceremony.
func (s *ossDeviceTrustService) EnrollDevice(stream devicepb.DeviceTrustService_EnrollDeviceServer) (retErr error) {
	ctx := stream.Context()
	authCtx, err := s.authorizeUser(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	user := authCtx.User.GetName()

	var dev *devicepb.Device
	defer func() {
		// Audit every attempt that got as far as identifying a device.
		if dev != nil {
			s.emitDeviceEvent(ctx, events.DeviceEnrollEvent, events.DeviceEnrollCode, dev, user, retErr)
		}
	}()

	req, err := stream.Recv()
	if err != nil {
		return trace.Wrap(err)
	}
	initReq := req.GetInit()
	switch {
	case initReq == nil:
		return trace.BadParameter("init required")
	case initReq.Token == "":
		return trace.BadParameter("token required")
	case initReq.CredentialId == "":
		return trace.BadParameter("credential ID required")
	}
	if err := validateDeviceData(initReq.DeviceData); err != nil {
		return trace.Wrap(err)
	}
	cd := initReq.DeviceData

	dev, err = s.findDeviceByOSTag(ctx, cd.OsType, cd.SerialNumber)
	if err != nil {
		return trace.Wrap(err)
	}

	// Verify and spend enrollment token.
	if err := s.spendEnrollToken(ctx, dev.Id, initReq.Token); err != nil {
		return trace.Wrap(err)
	}

	// OS-specific enrollment.
	var cred *devicepb.DeviceCredential
	switch cd.OsType {
	case devicepb.OSType_OS_TYPE_MACOS:
		cred, err = enrollMacOS(stream, initReq)
	case devicepb.OSType_OS_TYPE_LINUX, devicepb.OSType_OS_TYPE_WINDOWS:
		cred, err = enrollTPM(stream, initReq)
	default:
		return trace.BadParameter("unsupported OS type: %v", cd.OsType)
	}
	if err != nil {
		return trace.Wrap(err)
	}

	dev.UpdateTime = timestamppb.Now()
	dev.EnrollStatus = devicepb.DeviceEnrollStatus_DEVICE_ENROLL_STATUS_ENROLLED
	dev.Credential = cred
	// The device owner is the user who performed the enrollment.
	dev.Owner = user

	if err := s.putDevice(ctx, dev); err != nil {
		return trace.Wrap(err)
	}

	return trace.Wrap(stream.Send(&devicepb.EnrollDeviceResponse{
		Payload: &devicepb.EnrollDeviceResponse_Success{
			Success: &devicepb.EnrollDeviceSuccess{Device: dev},
		},
	}))
}

// AuthenticateDevice implements the server-side device authentication ceremony.
func (s *ossDeviceTrustService) AuthenticateDevice(stream devicepb.DeviceTrustService_AuthenticateDeviceServer) (retErr error) {
	ctx := stream.Context()
	authCtx, err := s.authorizeUser(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	var dev *devicepb.Device
	defer func() {
		if dev != nil {
			s.emitDeviceEvent(ctx, events.DeviceAuthenticateEvent, events.DeviceAuthenticateCode, dev, authCtx.User.GetName(), retErr)
		}
	}()

	req, err := stream.Recv()
	if err != nil {
		return trace.Wrap(err)
	}
	initReq := req.GetInit()
	switch {
	case initReq == nil:
		return trace.BadParameter("init required")
	case initReq.CredentialId == "":
		return trace.BadParameter("credential ID required")
	}
	if err := validateDeviceData(initReq.DeviceData); err != nil {
		return trace.Wrap(err)
	}

	dev, err = s.findDeviceByCredential(ctx, initReq.DeviceData, initReq.CredentialId)
	if err != nil {
		return trace.Wrap(err)
	}

	// Handle device web token if present.
	var confirmToken *devicepb.DeviceConfirmationToken
	if webToken := initReq.DeviceWebToken; webToken != nil {
		confirmToken, err = s.spendDeviceWebToken(webToken, dev)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	// OS-specific authentication.
	switch dev.OsType {
	case devicepb.OSType_OS_TYPE_MACOS:
		err = authenticateMacOS(dev, stream)
	case devicepb.OSType_OS_TYPE_LINUX, devicepb.OSType_OS_TYPE_WINDOWS:
		err = authenticateTPM(stream)
	default:
		err = fmt.Errorf("unsupported OS type: %v", dev.OsType)
	}
	if err != nil {
		return trace.Wrap(err)
	}

	if confirmToken != nil {
		return trace.Wrap(stream.Send(&devicepb.AuthenticateDeviceResponse{
			Payload: &devicepb.AuthenticateDeviceResponse_ConfirmationToken{
				ConfirmationToken: confirmToken,
			},
		}))
	}

	// Augment user certificates with device extensions.
	opts := &AugmentUserCertificateOpts{
		DeviceExtensions: &DeviceExtensions{
			DeviceID:     dev.Id,
			AssetTag:     dev.AssetTag,
			CredentialID: dev.Credential.Id,
		},
	}
	if initReq.UserCertificates != nil && len(initReq.UserCertificates.SshAuthorizedKey) > 0 {
		opts.SSHAuthorizedKey = initReq.UserCertificates.SshAuthorizedKey
		// The SSH key ownership was proven via the device challenge-response
		// ceremony (the client signs the challenge with both device key and SSH key).
		opts.SSHKeySatisfiedChallenge = true
	}

	certs, err := s.authServer.AugmentContextUserCertificates(ctx, authCtx, opts)
	if err != nil {
		return trace.Wrap(err)
	}

	// certs.TLS is PEM-encoded; the client expects DER bytes in X509Der.
	var tlsDER []byte
	if block, _ := pem.Decode(certs.TLS); block != nil {
		tlsDER = block.Bytes
	}

	return trace.Wrap(stream.Send(&devicepb.AuthenticateDeviceResponse{
		Payload: &devicepb.AuthenticateDeviceResponse_UserCertificates{
			UserCertificates: &devicepb.UserCertificates{
				X509Der:          tlsDER,
				SshAuthorizedKey: certs.SSH,
			},
		},
	}))
}

// ConfirmDeviceWebAuthentication confirms a device web authentication attempt.
func (s *ossDeviceTrustService) ConfirmDeviceWebAuthentication(ctx context.Context, req *devicepb.ConfirmDeviceWebAuthenticationRequest) (*devicepb.ConfirmDeviceWebAuthenticationResponse, error) {
	if _, err := s.authorizeUser(ctx); err != nil {
		return nil, trace.Wrap(err)
	}
	if req.ConfirmationToken == nil {
		return nil, trace.BadParameter("confirmation token required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	attempt, ok := s.webTokens[req.ConfirmationToken.Id]
	if !ok || attempt.confirmToken != req.ConfirmationToken.Token {
		return nil, trace.AccessDenied("invalid confirmation token")
	}

	delete(s.webTokens, req.ConfirmationToken.Id)
	return &devicepb.ConfirmDeviceWebAuthenticationResponse{}, nil
}

// CreateDeviceWebToken creates a device web token for the web auth flow.
func (s *ossDeviceTrustService) CreateDeviceWebToken(ctx context.Context, webToken *devicepb.DeviceWebToken) (*devicepb.DeviceWebToken, error) {
	if webToken == nil {
		return nil, nil
	}

	devices, err := s.listAllDevices(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var expectedDeviceID string
	for _, dev := range devices {
		if dev.Owner == webToken.User && dev.EnrollStatus == devicepb.DeviceEnrollStatus_DEVICE_ENROLL_STATUS_ENROLLED {
			expectedDeviceID = dev.Id
			break
		}
	}
	if expectedDeviceID == "" {
		return nil, nil
	}

	id := uuid.NewString()
	token := uuid.NewString()

	s.mu.Lock()
	s.webTokens[id] = &webAuthnAttempt{
		expectedDeviceID: expectedDeviceID,
		webSessionID:     webToken.WebSessionId,
		webToken:         token,
	}
	s.mu.Unlock()

	return &devicepb.DeviceWebToken{Id: id, Token: token}, nil
}

// CreateAssertCeremony creates a server-side device assertion ceremony.
func (s *ossDeviceTrustService) CreateAssertCeremony() (assertserver.Ceremony, error) {
	return &ossAssertCeremony{svc: s}, nil
}

// --- Assert ceremony implementation ---

type ossAssertCeremony struct {
	svc *ossDeviceTrustService
}

func (c *ossAssertCeremony) AssertDevice(ctx context.Context, stream assertserver.AssertDeviceServerStream) (*devicepb.Device, error) {
	req, err := stream.Recv()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	initReq := req.GetInit()
	switch {
	case initReq == nil:
		return nil, trace.BadParameter("init required")
	case initReq.CredentialId == "":
		return nil, trace.BadParameter("credential ID required")
	}
	if err := validateDeviceData(initReq.DeviceData); err != nil {
		return nil, trace.Wrap(err)
	}

	dev, err := c.svc.findDeviceByCredential(ctx, initReq.DeviceData, initReq.CredentialId)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch dev.OsType {
	case devicepb.OSType_OS_TYPE_MACOS:
		err = assertAuthenticateMacOS(dev, stream)
	case devicepb.OSType_OS_TYPE_LINUX, devicepb.OSType_OS_TYPE_WINDOWS:
		err = assertAuthenticateTPM(stream)
	default:
		err = fmt.Errorf("unsupported OS type: %v", dev.OsType)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := stream.Send(&devicepb.AssertDeviceResponse{
		Payload: &devicepb.AssertDeviceResponse_DeviceAsserted{},
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	return dev, nil
}

// --- Enrollment helpers ---

func enrollMacOS(stream devicepb.DeviceTrustService_EnrollDeviceServer, initReq *devicepb.EnrollDeviceInit) (*devicepb.DeviceCredential, error) {
	switch {
	case initReq.Macos == nil:
		return nil, trace.BadParameter("macOS data required")
	case len(initReq.Macos.PublicKeyDer) == 0:
		return nil, trace.BadParameter("macOS public key required")
	}

	pubKey, err := x509.ParsePKIXPublicKey(initReq.Macos.PublicKeyDer)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, trace.BadParameter("unexpected public key type: %T", pubKey)
	}

	chal, err := challenge.New()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := stream.Send(&devicepb.EnrollDeviceResponse{
		Payload: &devicepb.EnrollDeviceResponse_MacosChallenge{
			MacosChallenge: &devicepb.MacOSEnrollChallenge{Challenge: chal},
		},
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	chalResp := resp.GetMacosChallengeResponse()
	switch {
	case chalResp == nil:
		return nil, trace.BadParameter("challenge response required")
	case len(chalResp.Signature) == 0:
		return nil, trace.BadParameter("signature required")
	}
	if err := challenge.Verify(chal, chalResp.Signature, ecPubKey); err != nil {
		return nil, trace.BadParameter("signature verification failed")
	}

	return &devicepb.DeviceCredential{
		Id:           initReq.CredentialId,
		PublicKeyDer: initReq.Macos.PublicKeyDer,
	}, nil
}

func enrollTPM(stream devicepb.DeviceTrustService_EnrollDeviceServer, initReq *devicepb.EnrollDeviceInit) (*devicepb.DeviceCredential, error) {
	if initReq.Tpm == nil {
		return nil, trace.BadParameter("TPM data required")
	}

	secret, err := randomCryptoBytes()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	credentialBlob, err := randomCryptoBytes()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	expectedSolution := append(secret, credentialBlob...)
	nonce, err := randomCryptoBytes()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := stream.Send(&devicepb.EnrollDeviceResponse{
		Payload: &devicepb.EnrollDeviceResponse_TpmChallenge{
			TpmChallenge: &devicepb.TPMEnrollChallenge{
				EncryptedCredential: &devicepb.TPMEncryptedCredential{
					CredentialBlob: credentialBlob,
					Secret:         secret,
				},
				AttestationNonce: nonce,
			},
		},
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	chalResp := resp.GetTpmChallengeResponse()
	switch {
	case chalResp == nil:
		return nil, trace.BadParameter("challenge response required")
	case !bytes.Equal(expectedSolution, chalResp.Solution):
		return nil, trace.BadParameter("invalid TPM challenge solution")
	case chalResp.PlatformParameters == nil:
		return nil, trace.BadParameter("missing platform parameters")
	case !bytes.Equal(nonce, chalResp.PlatformParameters.EventLog):
		return nil, trace.BadParameter("nonce mismatch in challenge response")
	}

	return &devicepb.DeviceCredential{
		Id:                    initReq.CredentialId,
		DeviceAttestationType: devicepb.DeviceAttestationType_DEVICE_ATTESTATION_TYPE_TPM_EKPUB,
	}, nil
}

// --- Authentication helpers ---

func authenticateMacOS(dev *devicepb.Device, stream devicepb.DeviceTrustService_AuthenticateDeviceServer) error {
	if dev.Credential == nil || len(dev.Credential.PublicKeyDer) == 0 {
		return trace.BadParameter("device missing public key credential")
	}
	pubKey, err := x509.ParsePKIXPublicKey(dev.Credential.PublicKeyDer)
	if err != nil {
		return trace.Wrap(err)
	}

	chal, err := challenge.New()
	if err != nil {
		return trace.Wrap(err)
	}
	if err := stream.Send(&devicepb.AuthenticateDeviceResponse{
		Payload: &devicepb.AuthenticateDeviceResponse_Challenge{
			Challenge: &devicepb.AuthenticateDeviceChallenge{Challenge: chal},
		},
	}); err != nil {
		return trace.Wrap(err)
	}

	req, err := stream.Recv()
	if err != nil {
		return trace.Wrap(err)
	}
	chalResp := req.GetChallengeResponse()
	switch {
	case chalResp == nil:
		return trace.BadParameter("challenge response required")
	case len(chalResp.Signature) == 0:
		return trace.BadParameter("signature required")
	}
	return trace.Wrap(challenge.Verify(chal, chalResp.Signature, pubKey))
}

func authenticateTPM(stream devicepb.DeviceTrustService_AuthenticateDeviceServer) error {
	nonce, err := randomCryptoBytes()
	if err != nil {
		return trace.Wrap(err)
	}
	if err := stream.Send(&devicepb.AuthenticateDeviceResponse{
		Payload: &devicepb.AuthenticateDeviceResponse_TpmChallenge{
			TpmChallenge: &devicepb.TPMAuthenticateDeviceChallenge{AttestationNonce: nonce},
		},
	}); err != nil {
		return trace.Wrap(err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return trace.Wrap(err)
	}
	chalResp := resp.GetTpmChallengeResponse()
	switch {
	case chalResp == nil:
		return trace.BadParameter("challenge response required")
	case chalResp.PlatformParameters == nil:
		return trace.BadParameter("missing platform parameters")
	case !bytes.Equal(nonce, chalResp.PlatformParameters.EventLog):
		return trace.BadParameter("nonce mismatch")
	}
	return nil
}

// Assert-stream variants for the assertion ceremony (uses different proto types).

func assertAuthenticateMacOS(dev *devicepb.Device, stream assertserver.AssertDeviceServerStream) error {
	if dev.Credential == nil || len(dev.Credential.PublicKeyDer) == 0 {
		return trace.BadParameter("device missing public key credential")
	}
	pubKey, err := x509.ParsePKIXPublicKey(dev.Credential.PublicKeyDer)
	if err != nil {
		return trace.Wrap(err)
	}

	chal, err := challenge.New()
	if err != nil {
		return trace.Wrap(err)
	}
	if err := stream.Send(&devicepb.AssertDeviceResponse{
		Payload: &devicepb.AssertDeviceResponse_Challenge{
			Challenge: &devicepb.AuthenticateDeviceChallenge{Challenge: chal},
		},
	}); err != nil {
		return trace.Wrap(err)
	}

	req, err := stream.Recv()
	if err != nil {
		return trace.Wrap(err)
	}
	chalResp := req.GetChallengeResponse()
	switch {
	case chalResp == nil:
		return trace.BadParameter("challenge response required")
	case len(chalResp.Signature) == 0:
		return trace.BadParameter("signature required")
	}
	return trace.Wrap(challenge.Verify(chal, chalResp.Signature, pubKey))
}

func assertAuthenticateTPM(stream assertserver.AssertDeviceServerStream) error {
	nonce, err := randomCryptoBytes()
	if err != nil {
		return trace.Wrap(err)
	}
	if err := stream.Send(&devicepb.AssertDeviceResponse{
		Payload: &devicepb.AssertDeviceResponse_TpmChallenge{
			TpmChallenge: &devicepb.TPMAuthenticateDeviceChallenge{AttestationNonce: nonce},
		},
	}); err != nil {
		return trace.Wrap(err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return trace.Wrap(err)
	}
	chalResp := resp.GetTpmChallengeResponse()
	switch {
	case chalResp == nil:
		return trace.BadParameter("challenge response required")
	case chalResp.PlatformParameters == nil:
		return trace.BadParameter("missing platform parameters")
	case !bytes.Equal(nonce, chalResp.PlatformParameters.EventLog):
		return trace.BadParameter("nonce mismatch")
	}
	return nil
}

// --- Backend search helpers ---

func (s *ossDeviceTrustService) findDeviceByOSTag(ctx context.Context, osType devicepb.OSType, assetTag string) (*devicepb.Device, error) {
	devices, err := s.listAllDevices(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	for _, dev := range devices {
		if dev.OsType == osType && dev.AssetTag == assetTag {
			return dev, nil
		}
	}
	return nil, trace.NotFound("device not found")
}

func (s *ossDeviceTrustService) findDeviceByCredential(ctx context.Context, cd *devicepb.DeviceCollectedData, credentialID string) (*devicepb.Device, error) {
	dev, err := s.findDeviceByOSTag(ctx, cd.OsType, cd.SerialNumber)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if dev.Credential == nil || dev.Credential.Id != credentialID {
		return nil, trace.BadParameter("unknown credential for device")
	}
	return dev, nil
}

func (s *ossDeviceTrustService) spendDeviceWebToken(webToken *devicepb.DeviceWebToken, dev *devicepb.Device) (*devicepb.DeviceConfirmationToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	attempt, ok := s.webTokens[webToken.Id]
	if !ok {
		return nil, trace.AccessDenied("invalid device web token")
	}

	storedToken := attempt.webToken
	attempt.webToken = "" // Spend regardless of outcome.

	switch {
	case storedToken == "":
		return nil, trace.AccessDenied("invalid device web token")
	case storedToken != webToken.Token:
		return nil, trace.AccessDenied("invalid device web token")
	case attempt.expectedDeviceID != dev.Id:
		return nil, trace.AccessDenied("invalid device web token")
	}

	attempt.confirmToken = uuid.NewString()
	return &devicepb.DeviceConfirmationToken{
		Id:    attempt.webSessionID,
		Token: attempt.confirmToken,
	}, nil
}

// --- Utility functions ---

func validateDeviceData(cd *devicepb.DeviceCollectedData) error {
	switch {
	case cd == nil:
		return trace.BadParameter("device data required")
	case cd.OsType == devicepb.OSType_OS_TYPE_UNSPECIFIED:
		return trace.BadParameter("device OS type invalid")
	case cd.SerialNumber == "":
		return trace.BadParameter("device serial number required")
	}
	return nil
}

func randomCryptoBytes() ([]byte, error) {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	return buf, err
}

func cloneDevice(dev *devicepb.Device) *devicepb.Device {
	return &devicepb.Device{
		ApiVersion:   dev.ApiVersion,
		Id:           dev.Id,
		OsType:       dev.OsType,
		AssetTag:     dev.AssetTag,
		CreateTime:   dev.CreateTime,
		UpdateTime:   dev.UpdateTime,
		EnrollStatus: dev.EnrollStatus,
		Credential:   dev.Credential,
		Owner:        dev.Owner,
	}
}
