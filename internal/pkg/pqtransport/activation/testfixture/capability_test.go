// SPDX-License-Identifier: Apache-2.0

package testfixture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
)

func TestPQ40B1GenesisBinding(t *testing.T) {
	fixture := New(t)
	controller := fixture.Channel(nil, activation.Ledger{})
	legacy := Genesis(t)
	protected := TransportGenesis(t)
	require.NoError(t, controller.VerifyCapabilityBinding(legacy, legacy))
	require.NoError(t, controller.VerifyCapabilityBinding(protected, protected))
	require.ErrorContains(t, controller.VerifyCapabilityBinding(legacy, protected), "conflicts with genesis")
	require.ErrorContains(t, controller.VerifyCapabilityBinding(protected, legacy), "conflicts with genesis")
}

func TestPQ40B1AuthenticatedFreshGenesis(t *testing.T) {
	fixture := New(t)
	genesis := TransportGenesis(t)
	dir := t.TempDir()
	store, err := activation.OpenStore(dir, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, Config(t, genesis))
	id := sha256.Sum256([]byte(ChannelID))
	anchor, err := json.Marshal(hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("genesis-%x", id)), anchor, 0o600))
	controller := fixture.Channel(store, activation.Ledger{})
	require.NoError(t, controller.AuthorizeGenesis(genesis))
	require.Error(t, controller.AuthorizeGenesis(Genesis(t)))
}
