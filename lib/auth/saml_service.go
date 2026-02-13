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
	"context"
	"strings"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/utils/keys/hardwarekey"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/client/sso"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

// ossSAMLService implements SAMLService for OSS Teleport.
type ossSAMLService struct {
	a *Server
}

// CreateSAMLAuthRequest creates a new SAML auth request.
func (s *ossSAMLService) CreateSAMLAuthRequest(ctx context.Context, req types.SAMLAuthRequest) (*types.SAMLAuthRequest, error) {
	connector, err := s.getSAMLConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !req.CreateWebSession {
		ceremonyType := sso.CeremonyTypeLogin
		if req.SSOTestFlow {
			ceremonyType = sso.CeremonyTypeTest
		}
		if err := sso.ValidateClientRedirect(req.ClientRedirectURL, ceremonyType, connector.GetClientRedirectSettings()); err != nil {
			return nil, trace.Wrap(err, InvalidClientRedirectErrorMessage)
		}
	}

	req.ID, err = utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	sp, err := services.GetSAMLServiceProvider(connector, s.a.GetClock())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if connector.GetPreferredRequestBinding() == types.SAMLRequestHTTPPostBinding {
		postForm, err := sp.BuildAuthBodyPost(req.ID)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		req.PostForm = postForm
	} else {
		doc, err := sp.BuildAuthRequestDocumentNoSig()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		redirectURL, err := sp.BuildAuthURLRedirect(req.ID, doc)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		req.RedirectURL = redirectURL
	}

	if err := s.a.Services.CreateSAMLAuthRequest(ctx, req, defaults.SAMLAuthRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}

	return &req, nil
}

// CreateSAMLAuthRequestForMFA creates a new SAML auth request with MFA settings applied.
func (s *ossSAMLService) CreateSAMLAuthRequestForMFA(ctx context.Context, req types.SAMLAuthRequest) (*types.SAMLAuthRequest, error) {
	connector, err := s.getSAMLConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := connector.WithMFASettings(); err != nil {
		return nil, trace.Wrap(err)
	}

	if !req.CreateWebSession {
		ceremonyType := sso.CeremonyTypeLogin
		if req.SSOTestFlow {
			ceremonyType = sso.CeremonyTypeTest
		}
		if err := sso.ValidateClientRedirect(req.ClientRedirectURL, ceremonyType, connector.GetClientRedirectSettings()); err != nil {
			return nil, trace.Wrap(err, InvalidClientRedirectErrorMessage)
		}
	}

	req.ID, err = utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	sp, err := services.GetSAMLServiceProvider(connector, s.a.GetClock())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// MFA does not support HTTP-POST binding, always use redirect.
	doc, err := sp.BuildAuthRequestDocumentNoSig()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	redirectURL, err := sp.BuildAuthURLRedirect(req.ID, doc)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.RedirectURL = redirectURL

	if err := s.a.Services.CreateSAMLAuthRequest(ctx, req, defaults.SAMLAuthRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}

	return &req, nil
}

// ValidateSAMLResponse validates SAML auth response.
func (s *ossSAMLService) ValidateSAMLResponse(ctx context.Context, samlResponse, connectorID, clientIP string) (*authclient.SAMLAuthResponse, error) {
	diagCtx := NewSSODiagContext(types.KindSAML, s.a)

	event := &apievents.UserLogin{
		Metadata: apievents.Metadata{
			Type: events.UserLoginEvent,
		},
		Method:             events.LoginMethodSAML,
		ConnectionMetadata: authz.ConnectionMetadata(ctx),
	}

	auth, err := s.validateSAMLResponse(ctx, diagCtx, samlResponse, connectorID, clientIP)
	diagCtx.Info.Error = trace.UserMessage(err)
	event.AppliedLoginRules = diagCtx.Info.AppliedLoginRules

	diagCtx.WriteToBackend(ctx)

	if err != nil {
		event.Code = events.UserSSOLoginFailureCode
		if diagCtx.Info.TestFlow {
			event.Code = events.UserSSOTestFlowLoginFailureCode
		}
		event.Status.Success = false
		event.Status.Error = trace.Unwrap(err).Error()
		event.Status.UserMessage = err.Error()

		if auditErr := s.a.emitter.EmitAuditEvent(ctx, event); auditErr != nil {
			s.a.logger.WarnContext(ctx, "Failed to emit SAML login failed event", "error", auditErr)
		}
		return nil, trace.Wrap(err)
	}

	event.Code = events.UserSSOLoginCode
	if diagCtx.Info.TestFlow {
		event.Code = events.UserSSOTestFlowLoginCode
	}
	event.Status.Success = true
	event.User = auth.Username

	if auditErr := s.a.emitter.EmitAuditEvent(ctx, event); auditErr != nil {
		s.a.logger.WarnContext(ctx, "Failed to emit SAML login event", "error", auditErr)
	}

	return auth, nil
}

func (s *ossSAMLService) validateSAMLResponse(ctx context.Context, diagCtx *SSODiagContext, samlResponse, connectorID, clientIP string) (*authclient.SAMLAuthResponse, error) {
	// The samlResponse contains the RelayState (request ID) and actual SAML response
	// joined by a null byte separator. This encoding is done by the proxy's ACS handler.
	parts := strings.SplitN(samlResponse, "\x00", 2)
	if len(parts) != 2 {
		return nil, trace.BadParameter("invalid SAML response encoding")
	}
	requestID := parts[0]
	rawSAMLResponse := parts[1]

	diagCtx.RequestID = requestID

	connector, err := s.a.Services.GetSAMLConnector(ctx, connectorID, true)
	if err != nil {
		return nil, trace.Wrap(err, "failed to get SAML connector")
	}

	sp, err := services.GetSAMLServiceProvider(connector, s.a.GetClock())
	if err != nil {
		return nil, trace.Wrap(err, "failed to get SAML service provider")
	}

	assertionInfo, err := sp.RetrieveAssertionInfo(rawSAMLResponse)
	if err != nil {
		return nil, trace.Wrap(err, "failed to retrieve SAML assertion info")
	}

	if assertionInfo.WarningInfo.InvalidTime {
		s.a.logger.WarnContext(ctx, "SAML assertion expired")
		return nil, trace.BadParameter("SAML assertion expired")
	}
	if assertionInfo.WarningInfo.NotInAudience {
		s.a.logger.WarnContext(ctx, "SAML assertion not in audience")
		return nil, trace.BadParameter("SAML assertion audience mismatch")
	}

	req, err := s.a.Services.GetSAMLAuthRequest(ctx, requestID)
	if err != nil {
		return nil, trace.Wrap(err, "failed to get SAML auth request")
	}
	diagCtx.Info.TestFlow = req.SSOTestFlow

	traits := services.SAMLAssertionsToTraits(*assertionInfo)
	s.a.logger.InfoContext(ctx, "SAML assertions converted to traits", "traits", traits, "nameID", assertionInfo.NameID)
	diagCtx.Info.SAMLAttributesToRoles = connector.GetAttributesToRoles()

	warnings, roles := services.TraitsToRoles(connector.GetTraitMappings(), traits)
	if len(warnings) > 0 {
		s.a.logger.DebugContext(ctx, "SAML trait mapping warnings", "warnings", warnings)
	}
	s.a.logger.InfoContext(ctx, "SAML trait mapping result", "roles", roles, "warnings", warnings, "trait_mappings", connector.GetTraitMappings())
	if len(roles) == 0 {
		return nil, trace.AccessDenied("unable to map attributes to role for connector: %v", connectorID)
	}

	evaluationInput := &loginrule.EvaluationInput{
		Traits: traits,
	}
	evaluationOutput, err := s.a.GetLoginRuleEvaluator().Evaluate(ctx, evaluationInput)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	traits = evaluationOutput.Traits
	diagCtx.Info.AppliedLoginRules = evaluationOutput.AppliedRules

	roleset, err := services.FetchRoles(roles, s.a, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleTTL := roleset.AdjustSessionTTL(apidefaults.MaxCertDuration)
	sessionTTL := utils.MinTTL(roleTTL, req.CertTTL)

	diagCtx.Info.CreateUserParams = &types.CreateUserParams{
		ConnectorName: connectorID,
		Username:      assertionInfo.NameID,
		Roles:         roles,
		Traits:        traits,
		SessionTTL:    types.Duration(sessionTTL),
	}

	user, err := s.createSAMLUser(ctx, &CreateUserParams{
		ConnectorName: connectorID,
		Username:      assertionInfo.NameID,
		Roles:         roles,
		Traits:        traits,
		SessionTTL:    sessionTTL,
	}, req.SSOTestFlow)
	if err != nil {
		return nil, trace.Wrap(err, "failed to create user from SAML assertions")
	}

	if err := s.a.CallLoginHooks(ctx, user); err != nil {
		return nil, trace.Wrap(err)
	}

	userState, err := s.a.GetUserOrLoginState(ctx, user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if req.SSOTestFlow {
		diagCtx.Info.Success = true
		return &authclient.SAMLAuthResponse{
			Req: authclient.SAMLAuthRequest{
				ID:                req.ID,
				SSHPubKey:         req.SshPublicKey,
				TLSPubKey:         req.TlsPublicKey,
				CSRFToken:         req.CSRFToken,
				CreateWebSession:  req.CreateWebSession,
				ClientRedirectURL: req.ClientRedirectURL,
			},
			Identity: types.ExternalIdentity{
				ConnectorID: connectorID,
				Username:    assertionInfo.NameID,
			},
			Username: user.GetName(),
		}, nil
	}

	return s.makeSAMLAuthResponse(ctx, req, userState, assertionInfo.NameID, connectorID, sessionTTL)
}

func (s *ossSAMLService) makeSAMLAuthResponse(
	ctx context.Context,
	req *types.SAMLAuthRequest,
	userState services.UserState,
	nameID, connectorID string,
	sessionTTL time.Duration,
) (*authclient.SAMLAuthResponse, error) {
	auth := authclient.SAMLAuthResponse{
		Req: authclient.SAMLAuthRequest{
			ID:                req.ID,
			SSHPubKey:         req.SshPublicKey,
			TLSPubKey:         req.TlsPublicKey,
			CSRFToken:         req.CSRFToken,
			CreateWebSession:  req.CreateWebSession,
			ClientRedirectURL: req.ClientRedirectURL,
		},
		Identity: types.ExternalIdentity{
			ConnectorID: connectorID,
			Username:    nameID,
		},
		Username: userState.GetName(),
	}

	if req.CreateWebSession {
		session, err := s.a.CreateWebSessionFromReq(ctx, NewWebSessionRequest{
			User:                 userState.GetName(),
			Roles:                userState.GetRoles(),
			Traits:               userState.GetTraits(),
			SessionTTL:           sessionTTL,
			LoginTime:            s.a.clock.Now().UTC(),
			LoginIP:              req.ClientLoginIP,
			LoginUserAgent:       req.ClientUserAgent,
			AttestWebSession:     true,
			CreateDeviceWebToken: true,
			Scope:                req.Scope,
		})
		if err != nil {
			return nil, trace.Wrap(err, "failed to create web session")
		}
		auth.Session = session
	}

	if len(req.SshPublicKey) != 0 || len(req.TlsPublicKey) != 0 {
		sshCert, tlsCert, err := s.a.CreateSessionCerts(ctx, &SessionCertsRequest{
			UserState:               userState,
			SessionTTL:              sessionTTL,
			SSHPubKey:               req.SshPublicKey,
			TLSPubKey:               req.TlsPublicKey,
			SSHAttestationStatement: hardwarekey.AttestationStatementFromProto(req.SshAttestationStatement),
			TLSAttestationStatement: hardwarekey.AttestationStatementFromProto(req.TlsAttestationStatement),
			Compatibility:           req.Compatibility,
			RouteToCluster:          req.RouteToCluster,
			KubernetesCluster:       req.KubernetesCluster,
			LoginIP:                 req.ClientLoginIP,
			Scope:                   req.Scope,
		})
		if err != nil {
			return nil, trace.Wrap(err, "failed to create session certificate")
		}

		clusterName, err := s.a.GetClusterName(ctx)
		if err != nil {
			return nil, trace.Wrap(err, "failed to obtain cluster name")
		}

		auth.Cert = sshCert
		auth.TLSCert = tlsCert

		authority, err := s.a.GetCertAuthority(ctx, types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			return nil, trace.Wrap(err, "failed to obtain cluster's host CA")
		}
		auth.HostSigners = append(auth.HostSigners, authority)
	}

	if o, err := s.a.ClientOptionsForLogin(userState); err == nil {
		auth.ClientOptions = o
	} else {
		s.a.logger.WarnContext(ctx, "Failed to calculate client options for SAML login", "username", userState.GetName(), "error", err)
	}

	return &auth, nil
}

func (s *ossSAMLService) createSAMLUser(ctx context.Context, p *CreateUserParams, dryRun bool) (types.User, error) {
	s.a.logger.DebugContext(ctx, "Generating dynamic SAML identity",
		"connector_name", p.ConnectorName,
		"user_name", p.Username,
		"roles", p.Roles,
		"dry_run", dryRun,
	)

	expires := s.a.GetClock().Now().UTC().Add(p.SessionTTL)

	user := &types.UserV2{
		Kind:    types.KindUser,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      p.Username,
			Namespace: apidefaults.Namespace,
			Expires:   &expires,
		},
		Spec: types.UserSpecV2{
			Roles:  p.Roles,
			Traits: p.Traits,
			SAMLIdentities: []types.ExternalIdentity{{
				ConnectorID: p.ConnectorName,
				Username:    p.Username,
			}},
			CreatedBy: types.CreatedBy{
				User: types.UserRef{Name: teleport.UserSystem},
				Time: s.a.GetClock().Now().UTC(),
				Connector: &types.ConnectorRef{
					Type:     constants.SAML,
					ID:       p.ConnectorName,
					Identity: p.Username,
				},
			},
		},
	}

	if dryRun {
		return user, nil
	}

	existingUser, err := s.a.Services.GetUser(ctx, p.Username, false)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	if existingUser != nil {
		ref := user.GetCreatedBy().Connector
		if !ref.IsSameProvider(existingUser.GetCreatedBy().Connector) {
			return nil, trace.AlreadyExists("local user %q already exists and is not a SAML user",
				existingUser.GetName())
		}

		user.SetRevision(existingUser.GetRevision())
		if _, err := s.a.UpdateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if _, err := s.a.CreateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return user, nil
}

func (s *ossSAMLService) getSAMLConnector(ctx context.Context, req types.SAMLAuthRequest) (types.SAMLConnector, error) {
	if req.SSOTestFlow {
		if req.ConnectorSpec == nil {
			return nil, trace.BadParameter("ConnectorSpec cannot be nil for SSOTestFlow")
		}
		if req.ConnectorID == "" {
			return nil, trace.BadParameter("ConnectorID cannot be empty")
		}
		connector, err := types.NewSAMLConnector(req.ConnectorID, *req.ConnectorSpec)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return connector, nil
	}

	connector, err := s.a.Services.GetSAMLConnector(ctx, req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return connector, nil
}
