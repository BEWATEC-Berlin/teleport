// Teleport
// Copyright (C) 2026 Gravitational, Inc.
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

package auth

import (
	"context"
	"encoding/json"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/keys"
	"github.com/gravitational/teleport/lib/jwt"
	"github.com/gravitational/teleport/lib/services"
)

type dbscClaims struct {
	josejwt.Claims
}

// signDBSCChallenge creates a signed challenge.
func (a *Server) signDBSCChallenge(ctx context.Context, sessionID string) (string, error) {
	clusterName, err := a.GetClusterName(ctx)
	if err != nil {
		return "", trace.Wrap(err)
	}

	ca, err := a.GetCertAuthority(ctx, types.CertAuthID{
		Type:       types.JWTSigner,
		DomainName: clusterName.GetClusterName(),
	}, true)
	if err != nil {
		return "", trace.Wrap(err)
	}

	signer, err := a.GetKeyStore().GetJWTSigner(ctx, ca)
	if err != nil {
		return "", trace.Wrap(err)
	}

	privateKey, err := services.GetJWTSigner(signer, ca.GetClusterName(), a.clock)
	if err != nil {
		return "", trace.Wrap(err)
	}

	challenge, err := privateKey.SignDBSCChallenge(jwt.DBSCChallengeParams{
		SessionID: sessionID,
	})
	if err != nil {
		return "", trace.Wrap(err)
	}

	return challenge, nil
}

func (a *Server) verifyDBSCResponse(ctx context.Context, rawJWT string, sessionID string) ([]byte, error) {
	tok, err := josejwt.ParseSigned(rawJWT)
	if err != nil {
		return nil, trace.Wrap(err, "parsing DBSC response JWT")
	}

	if err := validateDBSCProofHeader(tok); err != nil {
		return nil, trace.Wrap(err)
	}

	var claims dbscClaims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, trace.Wrap(err, "extracting DBSC claims")
	}

	headerKey := tok.Headers[0].JSONWebKey
	if headerKey == nil {
		return nil, trace.BadParameter("missing jwk header in DBSC response")
	}

	publicKey := headerKey.Public()
	if err := tok.Claims(&publicKey, &claims); err != nil {
		return nil, trace.Wrap(err, "verifying DBSC response signature")
	}

	if claims.ID == "" {
		return nil, trace.BadParameter("missing jti claim (challenge) in DBSC response")
	}

	if err := a.verifyDBSCChallenge(ctx, claims.ID, sessionID); err != nil {
		return nil, trace.Wrap(err, "verifying DBSC challenge")
	}

	publicKeyJSON, err := json.Marshal(publicKey)
	if err != nil {
		return nil, trace.Wrap(err, "serializing public key")
	}

	return publicKeyJSON, nil
}

func (a *Server) verifyDBSCChallenge(ctx context.Context, challenge string, sessionID string) error {
	clusterName, err := a.GetClusterName(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	ca, err := a.GetCertAuthority(ctx, types.CertAuthID{
		Type:       types.JWTSigner,
		DomainName: clusterName.GetClusterName(),
	}, false)
	if err != nil {
		return trace.Wrap(err, "getting JWT CA")
	}

	var errs []error
	for _, kp := range ca.GetTrustedJWTKeyPairs() {
		publicKey, err := keys.ParsePublicKey(kp.PublicKey)
		if err != nil {
			errs = append(errs, trace.Wrap(err))
			continue
		}

		key, err := jwt.New(&jwt.Config{
			Clock:       a.clock,
			PublicKey:   publicKey,
			ClusterName: ca.GetClusterName(),
		})
		if err != nil {
			errs = append(errs, trace.Wrap(err))
			continue
		}

		err = key.VerifyDBSCChallenge(jwt.DBSCChallengeVerifyParams{
			RawToken:  challenge,
			SessionID: sessionID,
		})
		if err == nil {
			return nil
		}
		errs = append(errs, trace.Wrap(err))
	}

	if len(errs) == 0 {
		return trace.BadParameter("no JWT keys found in CA")
	}

	return trace.Wrap(trace.NewAggregate(errs...), "challenge verification failed")
}

func validateDBSCProofHeader(tok *josejwt.JSONWebToken) error {
	if len(tok.Headers) != 1 {
		return trace.BadParameter("invalid DBSC response JWT header count")
	}

	header := tok.Headers[0]
	// Chrome only supports ES256 currently (and we only send ES256 in our challenge), but the spec
	// says RS256 is also supported.
	if header.Algorithm != string(jose.ES256) && header.Algorithm != string(jose.RS256) {
		return trace.BadParameter("invalid DBSC response alg %q", header.Algorithm)
	}

	typ, ok := header.ExtraHeaders[jose.HeaderKey("typ")]
	if !ok {
		return trace.BadParameter("missing typ header in DBSC response")
	}

	typValue, ok := typ.(string)
	if !ok || typValue != "dbsc+jwt" {
		return trace.BadParameter("invalid typ header %v in DBSC response", typ)
	}

	return nil
}
