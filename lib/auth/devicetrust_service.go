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
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	devicepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/devicetrust/assertserver"
	"github.com/gravitational/teleport/lib/devicetrust/challenge"
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
type ossDeviceTrustService struct {
	devicepb.UnimplementedDeviceTrustServiceServer

	backend backend.Backend

	// mu protects in-memory enrollment tokens and web auth attempts.
	mu           sync.Mutex
	enrollTokens map[string]string // deviceID -> token
	webTokens    map[string]*webAuthnAttempt
}

type webAuthnAttempt struct {
	expectedDeviceID string
	webSessionID     string
	webToken         string
	confirmToken     string
}

func newOSSDeviceTrustService(b backend.Backend) *ossDeviceTrustService {
	return &ossDeviceTrustService{
		backend:      b,
		enrollTokens: make(map[string]string),
		webTokens:    make(map[string]*webAuthnAttempt),
	}
}

func deviceKey(id string) backend.Key {
	return backend.NewKey("devices", "id", id)
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

	if err := s.putDevice(ctx, created); err != nil {
		return nil, trace.Wrap(err)
	}

	if req.CreateEnrollToken {
		token := uuid.NewString()
		s.mu.Lock()
		s.enrollTokens[created.Id] = token
		s.mu.Unlock()

		resp := cloneDevice(created)
		resp.EnrollToken = &devicepb.DeviceEnrollToken{Token: token}
		return resp, nil
	}

	return created, nil
}

// UpdateDevice updates an existing device.
func (s *ossDeviceTrustService) UpdateDevice(ctx context.Context, req *devicepb.UpdateDeviceRequest) (*devicepb.Device, error) {
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
	return existing, nil
}

// UpsertDevice creates or updates a device.
func (s *ossDeviceTrustService) UpsertDevice(ctx context.Context, req *devicepb.UpsertDeviceRequest) (*devicepb.Device, error) {
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
	return dev, nil
}

// DeleteDevice removes a device.
func (s *ossDeviceTrustService) DeleteDevice(ctx context.Context, req *devicepb.DeleteDeviceRequest) (*emptypb.Empty, error) {
	if req.DeviceId == "" {
		return nil, trace.BadParameter("device ID required")
	}

	if err := s.backend.Delete(ctx, deviceKey(req.DeviceId)); err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.NotFound("device %q not found", req.DeviceId)
		}
		return nil, trace.Wrap(err)
	}

	s.mu.Lock()
	delete(s.enrollTokens, req.DeviceId)
	s.mu.Unlock()

	return &emptypb.Empty{}, nil
}

// GetDevice retrieves a device by ID.
func (s *ossDeviceTrustService) GetDevice(ctx context.Context, req *devicepb.GetDeviceRequest) (*devicepb.Device, error) {
	if req.DeviceId == "" {
		return nil, trace.BadParameter("device ID required")
	}
	return s.getDevice(ctx, req.DeviceId)
}

// ListDevices lists all devices.
func (s *ossDeviceTrustService) ListDevices(ctx context.Context, req *devicepb.ListDevicesRequest) (*devicepb.ListDevicesResponse, error) {
	devices, err := s.listAllDevices(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &devicepb.ListDevicesResponse{Devices: devices}, nil
}

// FindDevices searches for devices by ID or asset tag.
func (s *ossDeviceTrustService) FindDevices(ctx context.Context, req *devicepb.FindDevicesRequest) (*devicepb.FindDevicesResponse, error) {
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
func (s *ossDeviceTrustService) CreateDeviceEnrollToken(ctx context.Context, req *devicepb.CreateDeviceEnrollTokenRequest) (*devicepb.DeviceEnrollToken, error) {
	if req.DeviceId == "" {
		return nil, trace.BadParameter("device ID required")
	}

	if _, err := s.getDevice(ctx, req.DeviceId); err != nil {
		return nil, trace.Wrap(err)
	}

	token := uuid.NewString()
	s.mu.Lock()
	s.enrollTokens[req.DeviceId] = token
	s.mu.Unlock()

	return &devicepb.DeviceEnrollToken{Token: token}, nil
}

// EnrollDevice implements the server-side device enrollment ceremony.
func (s *ossDeviceTrustService) EnrollDevice(stream devicepb.DeviceTrustService_EnrollDeviceServer) error {
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

	dev, err := s.findDeviceByOSTag(stream.Context(), cd.OsType, cd.SerialNumber)
	if err != nil {
		return trace.Wrap(err)
	}

	// Verify and spend enrollment token.
	s.mu.Lock()
	storedToken, ok := s.enrollTokens[dev.Id]
	if !ok || storedToken != initReq.Token {
		s.mu.Unlock()
		return trace.AccessDenied("invalid device enrollment token")
	}
	delete(s.enrollTokens, dev.Id)
	s.mu.Unlock()

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
	if err := s.putDevice(stream.Context(), dev); err != nil {
		return trace.Wrap(err)
	}

	return trace.Wrap(stream.Send(&devicepb.EnrollDeviceResponse{
		Payload: &devicepb.EnrollDeviceResponse_Success{
			Success: &devicepb.EnrollDeviceSuccess{Device: dev},
		},
	}))
}

// AuthenticateDevice implements the server-side device authentication ceremony.
func (s *ossDeviceTrustService) AuthenticateDevice(stream devicepb.DeviceTrustService_AuthenticateDeviceServer) error {
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

	dev, err := s.findDeviceByCredential(stream.Context(), initReq.DeviceData, initReq.CredentialId)
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

	return trace.Wrap(stream.Send(&devicepb.AuthenticateDeviceResponse{
		Payload: &devicepb.AuthenticateDeviceResponse_UserCertificates{
			UserCertificates: &devicepb.UserCertificates{
				X509Der:          []byte("<augmented X.509 cert>"),
				SshAuthorizedKey: []byte("<augmented SSH cert>"),
			},
		},
	}))
}

// ConfirmDeviceWebAuthentication confirms a device web authentication attempt.
func (s *ossDeviceTrustService) ConfirmDeviceWebAuthentication(ctx context.Context, req *devicepb.ConfirmDeviceWebAuthenticationRequest) (*devicepb.ConfirmDeviceWebAuthenticationResponse, error) {
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
