/*
SPDX-License-Identifier: Apache-2.0
*/

package enrollment

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/protoutil"
)

const PeerSnapshotAnchorDomain = "fabric-pq/peer-snapshot/v1\x00"

// PeerSnapshotAnchor approves an exact Fabric state-transfer boundary. The
// supported boundary is a snapshot taken at the signed configuration block.
type PeerSnapshotAnchor struct {
	JoinAnchor
	SignableMetadataHash   string `json:"signable_metadata_hash"`
	AdditionalMetadataHash string `json:"additional_metadata_hash"`
}

type VerifiedPeerSnapshot struct {
	Channel       string
	Genesis       *cb.Block
	Configuration *cb.Block
	Files         map[string]string
}

// VerifyPeerSnapshot checks the raw native metadata against the signed anchor.
// The importer must also verify every file against the signed file hashes.
func (r *Registry) VerifyPeerSnapshot(signable, additional []byte, crypto bccsp.BCCSP) (*VerifiedPeerSnapshot, error) {
	var metadata struct {
		Channel     string            `json:"channel_name"`
		BlockNumber uint64            `json:"last_block_number"`
		BlockHash   string            `json:"last_block_hash"`
		Files       map[string]string `json:"snapshot_files_raw_hashes"`
	}
	if err := json.Unmarshal(signable, &metadata); err != nil {
		return nil, fmt.Errorf("decode peer snapshot metadata: %w", err)
	}
	controller := r.Controller(metadata.Channel, crypto)
	if controller == nil {
		return nil, errors.New("managed snapshot channel is not enrolled for protected onboarding")
	}
	var anchor PeerSnapshotAnchor
	if err := r.readJoinAnchor("join-peer", metadata.Channel, PeerSnapshotAnchorDomain, &anchor); err != nil {
		return nil, err
	}
	if anchor.SignableMetadataHash != fmt.Sprintf("%x", sha256.Sum256(signable)) ||
		anchor.AdditionalMetadataHash != fmt.Sprintf("%x", sha256.Sum256(additional)) {
		return nil, errors.New("snapshot metadata conflicts with signed peer join anchor")
	}
	genesis, err := controller.GenesisBlock()
	if err != nil {
		return nil, fmt.Errorf("verify genesis for peer snapshot: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(r.stateDir, joinEvidenceName("join-peer", metadata.Channel)+".block"))
	if err != nil {
		return nil, fmt.Errorf("read peer snapshot configuration block: %w", err)
	}
	block, err := protoutil.UnmarshalBlock(raw)
	if err != nil {
		return nil, err
	}
	expected, err := r.joinAnchor(controller, genesis, block)
	if err != nil {
		return nil, err
	}
	if anchor.JoinAnchor != expected || anchor.BlockNumber != metadata.BlockNumber || anchor.BlockHash != metadata.BlockHash {
		return nil, errors.New("peer snapshot boundary conflicts with signed genesis, configuration or node policy")
	}
	return &VerifiedPeerSnapshot{
		Channel: metadata.Channel, Genesis: genesis, Configuration: block, Files: metadata.Files,
	}, nil
}
