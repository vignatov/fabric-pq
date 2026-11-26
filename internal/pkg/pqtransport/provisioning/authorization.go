/*
SPDX-License-Identifier: Apache-2.0
*/

package provisioning

import (
	"crypto/mldsa"
	"errors"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport/exportauth"
)

const ExporterAuthorizationFormat = exportauth.AuthorizationFormat

type (
	ExporterAuthorization     = exportauth.Authorization
	ExporterExecution         = exportauth.Execution
	VerifiedExporterExecution = exportauth.VerifiedExecution
)

type VerifiedExporterAuthorization struct {
	verified *exportauth.VerifiedAuthorization
}

func SignExporterAuthorization(authorization ExporterAuthorization, signer *mldsa.PrivateKey) ([]byte, error) {
	return exportauth.SignAuthorization(authorization, signer)
}

func VerifyExporterAuthorization(encoded []byte, expectedAuthority string, authorityKey *mldsa.PublicKey) (*VerifiedExporterAuthorization, error) {
	verified, err := exportauth.VerifyAuthorization(encoded, expectedAuthority, authorityKey)
	if err != nil {
		return nil, err
	}
	return &VerifiedExporterAuthorization{verified: verified}, nil
}

func (v *VerifiedExporterAuthorization) Authorization() ExporterAuthorization {
	if v == nil {
		return ExporterAuthorization{}
	}
	return v.verified.Claims()
}

func (v *VerifiedExporterAuthorization) VerifyAuthorizedSourcePath() error {
	if v == nil {
		return errors.New("verified exporter authorization is required")
	}
	return v.verified.VerifySourcePath()
}

// SnapshotExporterTrust checks the authority's claims against verified history.
func (v *VerifiedExporterAuthorization) SnapshotExporterTrust(history *VerifiedJoinHistory) (*SnapshotExporterTrust, error) {
	if v == nil || v.verified == nil {
		return nil, errors.New("verified exporter authorization is required")
	}
	if history == nil || history.history == nil || !history.history.Verified() {
		return nil, errors.New("registry-bound verified Fabric history is required")
	}
	if !v.verified.MatchesAuthority(history.authorityIdentity, history.authorityKey) {
		return nil, errors.New("exporter authorization conflicts with independently enrolled authority")
	}
	identity, ok := history.history.JoinIdentity()
	if !ok {
		return nil, errors.New("verified Fabric join identity is unavailable")
	}
	report := history.Report()
	authorization := v.Authorization()
	if authorization.Network != identity.Network || authorization.Channel != identity.Channel ||
		authorization.TrustedGenesis != report.TrustedGenesisBlockIdentity ||
		authorization.SnapshotBlockNumber != report.TargetBlockNumber ||
		authorization.SnapshotBlockHash != report.TargetBlockHash ||
		authorization.ConfigurationSequence != report.TargetConfigurationSequence ||
		authorization.ConfigurationDigest != report.TargetConfigurationDigest ||
		authorization.SourceHistoryIdentity != report.SourceHistoryIdentity ||
		authorization.TransportProfile != identity.Profile {
		return nil, errors.New("exporter authorization conflicts with registry-bound Fabric history")
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), authorization.ExporterPublicKey)
	if err != nil {
		return nil, err
	}
	if history.history.MatchesSigner(key) {
		return nil, errors.New("snapshot exporter key must be independent of the policy signer")
	}
	return NewSnapshotExporterTrust(authorization.ExporterIdentity, authorization.SourceLedgerIdentity, key)
}

func SignExporterExecution(authorization *VerifiedExporterAuthorization, execution ExporterExecution, signer *mldsa.PrivateKey) ([]byte, error) {
	if authorization == nil {
		return nil, errors.New("verified exporter authorization is required")
	}
	return exportauth.SignExecution(authorization.verified, execution, signer)
}

func VerifyExporterExecution(authorization *VerifiedExporterAuthorization, encoded []byte) (*VerifiedExporterExecution, error) {
	if authorization == nil {
		return nil, errors.New("verified exporter authorization is required")
	}
	return exportauth.VerifyExecution(authorization.verified, encoded)
}
