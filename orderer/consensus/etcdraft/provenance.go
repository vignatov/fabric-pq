/*
Copyright the Hyperledger Fabric contributors. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package etcdraft

import (
	"errors"

	raftprotos "github.com/hyperledger/fabric-protos-go-apiv2/orderer/etcdraft"
	"github.com/hyperledger/fabric/common/channelconfig"
	"google.golang.org/protobuf/proto"
)

// ValidateHistoricalConsensusMetadata validates configuration metadata without
// assuming access to live Raft state. Membership readiness remains a runtime
// responsibility of the native orderer join and snapshot paths.
func ValidateHistoricalConsensusMetadata(previous, next channelconfig.Orderer) error {
	if next == nil {
		return errors.New("orderer configuration is missing")
	}
	if previous != nil && previous.ConsensusType() != next.ConsensusType() {
		return errors.New("consensus type changes are unsupported by offline provenance verification")
	}
	if next.ConsensusType() != "etcdraft" {
		return errors.New("only Raft consensus is supported by offline provenance verification")
	}
	if previous != nil && (previous.ConsensusType() != "etcdraft" || len(previous.ConsensusMetadata()) == 0) {
		return errors.New("preceding Raft configuration metadata is missing")
	}
	if len(next.ConsensusMetadata()) == 0 {
		return errors.New("Raft configuration metadata is missing")
	}
	metadata := &raftprotos.ConfigMetadata{}
	if err := proto.Unmarshal(next.ConsensusMetadata(), metadata); err != nil {
		return err
	}
	verifyOptions, err := createX509VerifyOptions(next)
	if err != nil {
		return err
	}
	if err := VerifyConfigMetadata(metadata, verifyOptions); err != nil {
		return err
	}
	return nil
}
