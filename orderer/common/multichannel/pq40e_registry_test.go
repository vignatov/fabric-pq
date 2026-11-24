// SPDX-License-Identifier: Apache-2.0

package multichannel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/orderer/common/localconfig"
	"github.com/stretchr/testify/require"
)

func TestPQ40EAuthenticatedRegistry(t *testing.T) {
	fixture := testfixture.New(t)
	dir := t.TempDir()
	store, err := activation.OpenStore(dir, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, testfixture.Config(t, testfixture.Genesis(t)))
	key := filepath.Join(dir, "policy-key")
	controller := fixture.Channel(store, activation.Ledger{})
	require.NoError(t, os.WriteFile(key, controller.Signer.Bytes(), 0o600))
	config := localconfig.PQActivation{
		StateDir: dir, TrustAnchor: key, Network: testfixture.Network, Node: testfixture.Node,
	}

	t.Run("membership comes from authenticated policy", func(t *testing.T) {
		registry := newProtectedChannels(config)
		require.NoError(t, registry.err)
		require.True(t, registry.contains(testfixture.ChannelID))
		require.ErrorContains(t, CheckProtectedStartup(config), "strict transport integration")
	})
	t.Run("ordinary configuration cannot add a channel", func(t *testing.T) {
		invalid := config
		invalid.Channels = []string{"unapproved"}
		require.ErrorContains(t, newProtectedChannels(invalid).err, "no authenticated binding")
	})
	t.Run("identity mismatch", func(t *testing.T) {
		invalid := config
		invalid.Node = "different-node"
		require.ErrorContains(t, newProtectedChannels(invalid).err, "bootstrap identity")
	})
	t.Run("untrusted signer", func(t *testing.T) {
		invalid := config
		invalid.TrustAnchor = filepath.Join(dir, "missing-key")
		require.ErrorContains(t, newProtectedChannels(invalid).err, "trust anchor")
	})
	t.Run("corrupt journal", func(t *testing.T) {
		path := filepath.Join(dir, "journal")
		require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))
		require.ErrorContains(t, newProtectedChannels(config).err, "activation journal")
		require.NoError(t, os.Remove(path))
	})
	t.Run("orphan durable record", func(t *testing.T) {
		path := filepath.Join(dir, "quarantine-unbound")
		require.NoError(t, os.WriteFile(path, []byte(`"reason"`), 0o600))
		require.ErrorContains(t, newProtectedChannels(config).err, "no authenticated channel binding")
		require.NoError(t, os.Remove(path))
	})
	t.Run("missing checkpoint", func(t *testing.T) {
		require.NoError(t, os.Remove(filepath.Join(dir, "checkpoint")))
		require.ErrorContains(t, newProtectedChannels(config).err, "protected checkpoint")
	})
}

func TestPQ40ELegacyStartup(t *testing.T) {
	require.NoError(t, CheckProtectedStartup(localconfig.PQActivation{}))
}
