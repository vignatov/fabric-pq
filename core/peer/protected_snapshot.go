/*
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/ledger/kvledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/protoutil"
)

// stageProtectedSnapshot authenticates both metadata files and copies only
// their approved payloads to a private import directory. The native import
// then verifies that same copy before writing ledger state.
func (p *Peer) stageProtectedSnapshot(sourceDir string) (channel, path string, cleanup func(), err error) {
	source, err := os.OpenRoot(sourceDir)
	if err != nil {
		return "", "", nil, err
	}
	defer source.Close()
	signable, err := source.ReadFile(kvledger.SnapshotSignableMetadataFileName)
	if err != nil {
		return "", "", nil, err
	}
	additional, err := source.ReadFile(kvledger.SnapshotAdditionalMetadataFileName)
	if err != nil {
		return "", "", nil, err
	}
	verified, err := p.ProtectedRegistry.VerifyPeerSnapshot(signable, additional, p.CryptoProvider)
	if err != nil {
		return "", "", nil, err
	}
	controller := p.ProtectedRegistry.Controller(verified.Channel, p.CryptoProvider)
	controller.Validate = validateProtectedPeerConfig
	if err := controller.AuthorizeBootstrapConfig(verified.Configuration); err != nil {
		return "", "", nil, err
	}
	stage, err := os.MkdirTemp(p.ProtectedRegistry.LedgerRoot(), ".protected-snapshot-")
	if err != nil {
		return "", "", nil, err
	}
	remove := func() {
		if err := os.RemoveAll(stage); err != nil {
			peerLogger.Warningf("Failed to remove staged protected snapshot: %s", err)
		}
	}
	defer func() {
		if err != nil {
			remove()
		}
	}()
	for name, digest := range verified.Files {
		if !filepath.IsLocal(name) || filepath.Base(name) != name ||
			name == kvledger.SnapshotSignableMetadataFileName || name == kvledger.SnapshotAdditionalMetadataFileName {
			return "", "", nil, errors.New("invalid protected snapshot payload file name")
		}
		if err := copyProtectedSnapshotFile(source, stage, name, digest); err != nil {
			return "", "", nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(stage, kvledger.SnapshotSignableMetadataFileName), signable, 0o600); err != nil {
		return "", "", nil, err
	}
	if err := os.WriteFile(filepath.Join(stage, kvledger.SnapshotAdditionalMetadataFileName), additional, 0o600); err != nil {
		return "", "", nil, err
	}
	return verified.Channel, stage, remove, nil
}

func copyProtectedSnapshotFile(source *os.Root, stage, name, digest string) error {
	info, err := source.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("protected snapshot payload %q is not a regular file", name)
	}
	input, err := source.Open(name)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(filepath.Join(stage, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	if err := errors.Join(copyErr, output.Close()); err != nil {
		return err
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != digest {
		return fmt.Errorf("protected snapshot payload %q conflicts with its signed digest", name)
	}
	return nil
}

func (p *Peer) recoverProtectedSnapshot(id string, l ledger.PeerLedger, info *cb.BlockchainInfo) (*enrollment.VerifiedPeerSnapshot, error) {
	signable, additional, err := p.LedgerMgr.BootstrapSnapshotMetadata(id)
	if err != nil {
		return nil, err
	}
	verified, err := p.ProtectedRegistry.VerifyPeerSnapshot(signable, additional, p.CryptoProvider)
	if err != nil {
		return nil, err
	}
	header := verified.Configuration.GetHeader()
	if verified.Channel != id || info.GetBootstrappingSnapshotInfo().GetLastBlockInSnapshot() != header.GetNumber() {
		return nil, errors.New("native ledger conflicts with the signed snapshot channel or height")
	}
	hash := protoutil.BlockHeaderHash(header)
	if info.GetHeight() == header.GetNumber()+1 {
		if !bytes.Equal(info.GetCurrentBlockHash(), hash) {
			return nil, errors.New("native snapshot tip conflicts with the signed configuration block")
		}
	} else {
		first, err := l.GetBlockByNumber(header.GetNumber() + 1)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(first.GetHeader().GetPreviousHash(), hash) {
			return nil, errors.New("post-snapshot ledger does not extend the signed configuration block")
		}
	}
	return verified, nil
}
