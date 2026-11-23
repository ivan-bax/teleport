//go:build tpmsimulator

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

// SAML-OSS fork: TPM enrollment and authentication against a software TPM.
// Requires cgo and the openssl headers:
//
//	go test ./lib/auth -run TestDeviceTrustService_TPM -tags tpmsimulator

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-attestation/attest"
	tpmsimulator "github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	devicepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/devicetrust"
)

type simCmdChannel struct{ io.ReadWriteCloser }

func (*simCmdChannel) MeasurementLog() ([]byte, error) { return nil, nil }

// fakeBidiStream is a server stream whose client side is a function that
// answers the last message the server sent.
type fakeBidiStream[Req, Resp any] struct {
	grpc.ServerStream
	ctx     context.Context
	first   *Req
	last    *Resp
	respond func(*Resp) (*Req, error)
}

func (f *fakeBidiStream[Req, Resp]) Context() context.Context { return f.ctx }
func (f *fakeBidiStream[Req, Resp]) Send(r *Resp) error       { f.last = r; return nil }
func (f *fakeBidiStream[Req, Resp]) Recv() (*Req, error) {
	if f.first != nil {
		r := f.first
		f.first = nil
		return r, nil
	}
	return f.respond(f.last)
}

// simDevice mimics lib/devicetrust/native's TPM client on a simulated TPM.
type simDevice struct {
	t      *testing.T
	tpm    *attest.TPM
	ak     *attest.AK
	ekPub  []byte
	ekCert []byte
	serial string
}

func newSimDevice(t *testing.T, tpm *attest.TPM, serial string) *simDevice {
	t.Helper()
	ak, err := tpm.NewAK(&attest.AKConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { ak.Close(tpm) })
	eks, err := tpm.EKs()
	require.NoError(t, err)
	ekPub, err := x509.MarshalPKIXPublicKey(eks[0].Public)
	require.NoError(t, err)
	d := &simDevice{t: t, tpm: tpm, ak: ak, ekPub: ekPub, serial: serial}
	if eks[0].Certificate != nil {
		d.ekCert = eks[0].Certificate.Raw
	}
	return d
}

// credentialID is computed independently of the server's tpmCredentialID, the
// same way native.credentialIDFromAK does.
func (d *simDevice) credentialID() string {
	akPub, err := attest.ParseAKPublic(d.ak.AttestationParameters().Public)
	require.NoError(d.t, err)
	pub := akPub.Public.(*rsa.PublicKey)
	h := sha256.New()
	h.Write(big.NewInt(int64(pub.E)).Bytes())
	h.Write(pub.N.Bytes())
	return base64.RawStdEncoding.EncodeToString(h.Sum(nil))
}

func (d *simDevice) collectedData() *devicepb.DeviceCollectedData {
	return &devicepb.DeviceCollectedData{OsType: devicepb.OSType_OS_TYPE_LINUX, SerialNumber: d.serial}
}

func (d *simDevice) enrollInit(token string) *devicepb.EnrollDeviceInit {
	payload := &devicepb.TPMEnrollPayload{
		AttestationParameters: devicetrust.AttestationParametersToProto(d.ak.AttestationParameters()),
	}
	if d.ekCert != nil {
		payload.Ek = &devicepb.TPMEnrollPayload_EkCert{EkCert: d.ekCert}
	} else {
		payload.Ek = &devicepb.TPMEnrollPayload_EkKey{EkKey: d.ekPub}
	}
	return &devicepb.EnrollDeviceInit{
		Token:        token,
		CredentialId: d.credentialID(),
		DeviceData:   d.collectedData(),
		Tpm:          payload,
	}
}

func (d *simDevice) attest(nonce []byte) *devicepb.TPMPlatformParameters {
	pp, err := d.tpm.AttestPlatform(d.ak, nonce, &attest.PlatformAttestConfig{EventLog: []byte{}})
	require.NoError(d.t, err)
	return devicetrust.PlatformParametersToProto(pp)
}

func (d *simDevice) solveEnroll(resp *devicepb.EnrollDeviceResponse) (*devicepb.EnrollDeviceRequest, error) {
	chal := resp.GetTpmChallenge()
	if chal == nil {
		return nil, trace.BadParameter("unexpected server message %T", resp.Payload)
	}
	solution, err := d.ak.ActivateCredential(d.tpm, *devicetrust.EncryptedCredentialFromProto(chal.EncryptedCredential))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &devicepb.EnrollDeviceRequest{
		Payload: &devicepb.EnrollDeviceRequest_TpmChallengeResponse{
			TpmChallengeResponse: &devicepb.TPMEnrollChallengeResponse{
				Solution:           solution,
				PlatformParameters: d.attest(chal.AttestationNonce),
			},
		},
	}, nil
}

func (d *simDevice) solveAuthn(resp *devicepb.AuthenticateDeviceResponse) (*devicepb.AuthenticateDeviceRequest, error) {
	chal := resp.GetTpmChallenge()
	if chal == nil {
		return nil, trace.BadParameter("unexpected server message %T", resp.Payload)
	}
	return &devicepb.AuthenticateDeviceRequest{
		Payload: &devicepb.AuthenticateDeviceRequest_TpmChallengeResponse{
			TpmChallengeResponse: &devicepb.TPMAuthenticateDeviceChallengeResponse{
				PlatformParameters: d.attest(chal.AttestationNonce),
			},
		},
	}, nil
}

func enrollStream(init *devicepb.EnrollDeviceInit, respond func(*devicepb.EnrollDeviceResponse) (*devicepb.EnrollDeviceRequest, error)) *fakeBidiStream[devicepb.EnrollDeviceRequest, devicepb.EnrollDeviceResponse] {
	return &fakeBidiStream[devicepb.EnrollDeviceRequest, devicepb.EnrollDeviceResponse]{
		ctx:     context.Background(),
		first:   &devicepb.EnrollDeviceRequest{Payload: &devicepb.EnrollDeviceRequest_Init{Init: init}},
		respond: respond,
	}
}

func simAuthnStream(respond func(*devicepb.AuthenticateDeviceResponse) (*devicepb.AuthenticateDeviceRequest, error)) *fakeBidiStream[devicepb.AuthenticateDeviceRequest, devicepb.AuthenticateDeviceResponse] {
	return &fakeBidiStream[devicepb.AuthenticateDeviceRequest, devicepb.AuthenticateDeviceResponse]{
		ctx:     context.Background(),
		respond: respond,
	}
}

// registerTPMDevice registers a Linux device and returns an enroll token.
func registerTPMDevice(t *testing.T, s *ossDeviceTrustService, serial string) string {
	t.Helper()
	dev, err := s.CreateDevice(context.Background(), &devicepb.CreateDeviceRequest{
		Device:            &devicepb.Device{OsType: devicepb.OSType_OS_TYPE_LINUX, AssetTag: serial},
		CreateEnrollToken: true,
	})
	require.NoError(t, err)
	return dev.EnrollToken.Token
}

func writeSimEKCert(t *testing.T, sim io.ReadWriter, der []byte) {
	t.Helper()
	const nvIndex = 0x1c00002 // TCG RSA 2048 EK certificate index.
	require.NoError(t, tpm2.NVDefineSpace(sim, tpm2.HandlePlatform, nvIndex, "", "", nil,
		tpm2.AttrPPWrite|tpm2.AttrPPRead|tpm2.AttrPlatformCreate|tpm2.AttrAuthRead, uint16(len(der))))
	require.NoError(t, tpm2.NVWrite(sim, tpm2.HandlePlatform, nvIndex, "", der, 0))
}

// TestDeviceTrustService_TPM runs as a single test because the TPM simulator
// is a process-wide singleton.
func TestDeviceTrustService_TPM(t *testing.T) {
	ctx := context.Background()

	sim, err := tpmsimulator.GetWithFixedSeedInsecure(0)
	require.NoError(t, err)
	simTPM, err := attest.OpenTPM(&attest.OpenConfig{CommandChannel: &simCmdChannel{ReadWriteCloser: sim}})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, simTPM.Close()) })

	t.Run("enroll, authenticate and assert", func(t *testing.T) {
		s := newTestDeviceTrustService(t)
		d := newSimDevice(t, simTPM, "LINUX1")
		token := registerTPMDevice(t, s, d.serial)

		asUser(s, userCtx(t, "llama"))
		require.NoError(t, s.EnrollDevice(enrollStream(d.enrollInit(token), d.solveEnroll)))

		asUser(s, userCtx(t, "admin", deviceAdminVerbs...))
		dev, err := s.findDeviceByOSTag(ctx, devicepb.OSType_OS_TYPE_LINUX, d.serial)
		require.NoError(t, err)
		assert.Equal(t, devicepb.DeviceEnrollStatus_DEVICE_ENROLL_STATUS_ENROLLED, dev.EnrollStatus)
		assert.Equal(t, "llama", dev.Owner)
		assert.Equal(t, d.credentialID(), dev.Credential.Id)
		assert.Equal(t, devicepb.DeviceAttestationType_DEVICE_ATTESTATION_TYPE_TPM_EKPUB, dev.Credential.DeviceAttestationType)
		assert.Equal(t, d.ak.AttestationParameters().Public, dev.Credential.TpmAkPublic)

		_, _, err = authenticateTPM(dev, simAuthnStream(d.solveAuthn))
		require.NoError(t, err)

		assertStream := &fakeBidiStream[devicepb.AssertDeviceRequest, devicepb.AssertDeviceResponse]{
			ctx: ctx,
			first: &devicepb.AssertDeviceRequest{Payload: &devicepb.AssertDeviceRequest_Init{
				Init: &devicepb.AssertDeviceInit{CredentialId: d.credentialID(), DeviceData: d.collectedData()},
			}},
			respond: func(resp *devicepb.AssertDeviceResponse) (*devicepb.AssertDeviceRequest, error) {
				nonce := resp.GetTpmChallenge().GetAttestationNonce()
				return &devicepb.AssertDeviceRequest{Payload: &devicepb.AssertDeviceRequest_TpmChallengeResponse{
					TpmChallengeResponse: &devicepb.TPMAuthenticateDeviceChallengeResponse{PlatformParameters: d.attest(nonce)},
				}}, nil
			},
		}
		ceremony, err := s.CreateAssertCeremony()
		require.NoError(t, err)
		asserted, err := ceremony.AssertDevice(ctx, assertStream)
		require.NoError(t, err)
		assert.Equal(t, dev.Id, asserted.Id)

		t.Run("another TPM key can't authenticate as the device", func(t *testing.T) {
			// The attacker knows serial and credential ID, but quotes with
			// their own AK.
			attacker := newSimDevice(t, simTPM, d.serial)
			_, _, err := authenticateTPM(dev, simAuthnStream(attacker.solveAuthn))
			assert.True(t, trace.IsAccessDenied(err), "got %v", err)
		})

		t.Run("a replayed quote is rejected", func(t *testing.T) {
			stale := d.attest([]byte("an-old-nonce-from-a-past-session"))
			_, _, err := authenticateTPM(dev, simAuthnStream(func(*devicepb.AuthenticateDeviceResponse) (*devicepb.AuthenticateDeviceRequest, error) {
				return &devicepb.AuthenticateDeviceRequest{Payload: &devicepb.AuthenticateDeviceRequest_TpmChallengeResponse{
					TpmChallengeResponse: &devicepb.TPMAuthenticateDeviceChallengeResponse{PlatformParameters: stale},
				}}, nil
			}))
			assert.True(t, trace.IsAccessDenied(err), "got %v", err)
		})

		t.Run("missing platform parameters are rejected", func(t *testing.T) {
			_, _, err := authenticateTPM(dev, simAuthnStream(func(*devicepb.AuthenticateDeviceResponse) (*devicepb.AuthenticateDeviceRequest, error) {
				return &devicepb.AuthenticateDeviceRequest{Payload: &devicepb.AuthenticateDeviceRequest_TpmChallengeResponse{
					TpmChallengeResponse: &devicepb.TPMAuthenticateDeviceChallengeResponse{},
				}}, nil
			}))
			assert.Error(t, err)
		})

		t.Run("device without a stored AK must re-enroll", func(t *testing.T) {
			legacy := cloneDevice(dev)
			legacy.Credential = &devicepb.DeviceCredential{Id: dev.Credential.Id}
			_, _, err := authenticateTPM(legacy, simAuthnStream(d.solveAuthn))
			assert.True(t, trace.IsAccessDenied(err), "got %v", err)
		})
	})

	t.Run("enroll rejections", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			mutate  func(d *simDevice, init *devicepb.EnrollDeviceInit)
			respond func(d *simDevice) func(*devicepb.EnrollDeviceResponse) (*devicepb.EnrollDeviceRequest, error)
		}{
			{
				name: "plaintext-style solution (old fork protocol)",
				respond: func(d *simDevice) func(*devicepb.EnrollDeviceResponse) (*devicepb.EnrollDeviceRequest, error) {
					return func(resp *devicepb.EnrollDeviceResponse) (*devicepb.EnrollDeviceRequest, error) {
						ec := resp.GetTpmChallenge().GetEncryptedCredential()
						return &devicepb.EnrollDeviceRequest{Payload: &devicepb.EnrollDeviceRequest_TpmChallengeResponse{
							TpmChallengeResponse: &devicepb.TPMEnrollChallengeResponse{
								Solution:           append(append([]byte{}, ec.Secret...), ec.CredentialBlob...),
								PlatformParameters: d.attest(resp.GetTpmChallenge().AttestationNonce),
							},
						}}, nil
					}
				},
			},
			{
				name: "credential ID not derived from the AK",
				mutate: func(_ *simDevice, init *devicepb.EnrollDeviceInit) {
					init.CredentialId = "someone-elses-credential"
				},
			},
			{
				name: "EK that isn't in this TPM",
				mutate: func(_ *simDevice, init *devicepb.EnrollDeviceInit) {
					//nolint:forbidigo // RSA EK stand-in.
					key, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)
					ek, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
					require.NoError(t, err)
					init.Tpm.Ek = &devicepb.TPMEnrollPayload_EkKey{EkKey: ek}
				},
			},
			{
				name: "platform attestation over the wrong nonce",
				respond: func(d *simDevice) func(*devicepb.EnrollDeviceResponse) (*devicepb.EnrollDeviceRequest, error) {
					return func(resp *devicepb.EnrollDeviceResponse) (*devicepb.EnrollDeviceRequest, error) {
						req, err := d.solveEnroll(resp)
						if err != nil {
							return nil, err
						}
						req.GetTpmChallengeResponse().PlatformParameters = d.attest([]byte("not-the-server-nonce"))
						return req, nil
					}
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := newTestDeviceTrustService(t)
				d := newSimDevice(t, simTPM, "LINUX-"+tc.name)
				token := registerTPMDevice(t, s, d.serial)
				init := d.enrollInit(token)
				if tc.mutate != nil {
					tc.mutate(d, init)
				}
				respond := d.solveEnroll
				if tc.respond != nil {
					respond = tc.respond(d)
				}
				require.Error(t, s.EnrollDevice(enrollStream(init, respond)))

				dev, err := s.findDeviceByOSTag(ctx, devicepb.OSType_OS_TYPE_LINUX, d.serial)
				require.NoError(t, err)
				assert.NotEqual(t, devicepb.DeviceEnrollStatus_DEVICE_ENROLL_STATUS_ENROLLED, dev.EnrollStatus)
				assert.Nil(t, dev.Credential)
			})
		}
	})

	// From here on the simulated TPM carries an EKCert signed by caPEM.
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
	}
	//nolint:forbidigo // Test CA.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	eks, err := simTPM.EKs()
	require.NoError(t, err)
	ekCertDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0x1337),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, ca, eks[0].Public, caKey)
	require.NoError(t, err)
	writeSimEKCert(t, sim, ekCertDER)

	//nolint:forbidigo // Unrelated CA.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &otherKey.PublicKey, otherKey)
	require.NoError(t, err)
	otherPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER}))

	for _, tc := range []struct {
		name      string
		allowed   []string
		wantErr   bool
		wantType  devicepb.DeviceAttestationType
		ekKeyOnly bool
	}{
		{name: "EKCert, no CA allow list", wantType: devicepb.DeviceAttestationType_DEVICE_ATTESTATION_TYPE_TPM_EKCERT},
		{name: "EKCert signed by an allowed CA", allowed: []string{caPEM}, wantType: devicepb.DeviceAttestationType_DEVICE_ATTESTATION_TYPE_TPM_EKCERT_TRUSTED},
		{name: "EKCert signed by another CA", allowed: []string{otherPEM}, wantErr: true},
		{name: "EK key only with a CA allow list", allowed: []string{caPEM}, ekKeyOnly: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestDeviceTrustService(t)
			setDeviceTrust(t, s, &types.DeviceTrust{Mode: "optional", EKCertAllowedCAs: tc.allowed})
			d := newSimDevice(t, simTPM, "LINUX-"+tc.name)
			require.NotNil(t, d.ekCert)
			if tc.ekKeyOnly {
				d.ekCert = nil
			}
			token := registerTPMDevice(t, s, d.serial)
			err := s.EnrollDevice(enrollStream(d.enrollInit(token), d.solveEnroll))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			dev, err := s.findDeviceByOSTag(ctx, devicepb.OSType_OS_TYPE_LINUX, d.serial)
			require.NoError(t, err)
			assert.Equal(t, tc.wantType, dev.Credential.DeviceAttestationType)
			assert.Equal(t, "13:37", dev.Credential.TpmEkcertSerial)
		})
	}
}
