//go:build linux

/*
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/metrics/disabled"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/common/ledger/blockledger/fileledger"
	"github.com/hyperledger/fabric/core/config/configtest"
	coreledger "github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/activation/testfixture"
	"github.com/hyperledger/fabric/internal/pkg/pqtransport/enrollment"
	"github.com/hyperledger/fabric/orderer/common/types"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/require"
)

// This test installs the actual managed service at its production paths on a
// fresh hosted runner VM. The ordinary test suite never opts into it.
func TestPQ40EDisposableVMService(t *testing.T) {
	if os.Getenv("PQ40E_DISPOSABLE_VM") != "1" {
		t.Skip("requires a disposable systemd VM and the native test binaries")
	}
	require.Equal(t, 0, os.Geteuid())
	require.DirExists(t, "/run/systemd/system")
	const (
		unit        = "fabric-pq-managed.service"
		unitPath    = "/etc/systemd/system/" + unit
		provision   = "/etc/fabric-pq"
		config      = provision + "/fabric"
		evidence    = provision + "/enrollment"
		runtimeRoot = "/var/lib/fabric-pq"
		state       = runtimeRoot + "/state"
		ledger      = runtimeRoot + "/ledger"
		installRoot = "/usr/local/libexec/fabric-pq"
		staging     = provision + "/ci-install"
	)
	assets := os.Getenv("PQ40E_VM_ASSETS")
	require.True(t, filepath.IsAbs(assets))
	for _, path := range []string{unitPath, provision, runtimeRoot, installRoot, staging} {
		_, err := os.Lstat(path)
		require.ErrorIs(t, err, os.ErrNotExist, "use a fresh disposable VM")
	}
	run := func(name string, args ...string) string {
		t.Helper()
		data, err := exec.CommandContext(t.Context(), name, args...).CombinedOutput()
		require.NoError(t, err, "%s: %s", name, data)
		return strings.TrimSpace(string(data))
	}
	write := func(path string, data []byte, mode os.FileMode) {
		t.Helper()
		require.NoError(t, os.WriteFile(path, data, mode))
	}
	run("useradd", "--system", "--user-group", "--shell", "/usr/sbin/nologin", "fabric-pq")
	account, err := user.Lookup("fabric-pq")
	require.NoError(t, err)
	uid, err := strconv.Atoi(account.Uid)
	require.NoError(t, err)
	gid, err := strconv.Atoi(account.Gid)
	require.NoError(t, err)
	for _, path := range []string{config, evidence, state, ledger, installRoot, staging + "/sampleconfig", staging + "/scripts"} {
		require.NoError(t, os.MkdirAll(path, 0o755))
	}
	root := filepath.Dir(configtest.GetDevConfigDir())
	run("install", "-m", "0644", filepath.Join(root, "sampleconfig", unit), staging+"/sampleconfig/"+unit)
	run("install", "-m", "0755", filepath.Join(root, "scripts", "install-pq-managed-service.sh"), staging+"/scripts/install-pq-managed-service.sh")
	run("install", "-m", "0755", filepath.Join(assets, "orderer"), installRoot+"/orderer")
	run("install", "-m", "0755", filepath.Join(assets, "pq-launcher"), staging+"/pq-launcher")
	require.NoError(t, os.CopyFS(config+"/msp", os.DirFS(configtest.GetDevMspDir())))

	ca, err := tlsgen.NewMLDSA65CA()
	require.NoError(t, err)
	server, err := ca.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)
	clientKey, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)
	write(config+"/ca.crt", ca.CertBytes(), 0o644)
	write(config+"/tls.crt", server.Cert, 0o644)
	write(config+"/tls.key", server.Key, 0o640)
	require.NoError(t, os.Chown(config+"/tls.key", 0, gid))
	mainPort, adminPort, opsPort := unusedPort(t), unusedPort(t), unusedPort(t)
	tlsConfig := "    Enabled: true\n    Certificate: tls.crt\n    PrivateKey: tls.key\n    ClientAuthRequired: true\n    ClientRootCAs: [ca.crt]\n"
	ordinaryConfig := fmt.Sprintf("General:\n  ListenAddress: 127.0.0.1\n  ListenPort: %s\n  BootstrapMethod: none\n  LocalMSPID: SampleOrg\n  LocalMSPDir: msp\n  TLS:\n%s  Cluster:\n    RootCAs: [ca.crt]\nFileLedger:\n  Location: %s\nConsensus:\n  WALDir: %s/wal\n  SnapDir: %s/snap\nAdmin:\n  ListenAddress: 127.0.0.1:%s\n  TLS:\n%sOperations:\n  ListenAddress: 127.0.0.1:%s\n  TLS:\n%s",
		mainPort, tlsConfig, ledger, ledger, ledger, adminPort, tlsConfig, opsPort, tlsConfig)
	write(config+"/orderer.yaml", []byte(ordinaryConfig), 0o644)

	fixture := testfixture.New(t)
	genesis := managedGenesis(t, fixture, ca.CertBytes(), server.Cert, mainPort)
	factory, err := fileledger.New(ledger, coreledger.GoLevelDB, &disabled.Provider{})
	require.NoError(t, err)
	l, err := factory.GetOrCreate(testfixture.ChannelID)
	require.NoError(t, err)
	require.NoError(t, l.Append(genesis))
	factory.Close()
	store, err := activation.OpenStore(state, nil)
	require.NoError(t, err)
	fixture.Provision(t, store, testfixture.Config(t, genesis))
	genesisHash, err := json.Marshal(hex.EncodeToString(protoutil.BlockHeaderHash(genesis.GetHeader())))
	require.NoError(t, err)
	write(fmt.Sprintf("%s/genesis-%x", state, sha256.Sum256([]byte(testfixture.ChannelID))), genesisHash, 0o600)
	run("chown", "-R", "fabric-pq:fabric-pq", state, ledger)
	policy := fixture.Channel(store, activation.Ledger{}).Signer.Bytes()
	write(evidence+"/policy.pub", policy, 0o644)
	authority, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	write(evidence+"/authority.pub", authority.Public().(*mldsa.PublicKey).Bytes(), 0o644)
	manifest := enrollment.Manifest{
		Network: testfixture.Network, Node: testfixture.Node, Generation: 1, Mode: enrollment.Protected,
		Executable: installRoot + "/orderer", Arguments: []string{"start"}, Profile: pqtransport.ProfileV1,
		PolicySigner: evidence + "/policy.pub", PolicySignerDigest: fmt.Sprintf("%x", sha256.Sum256(policy)),
		StateDir: state, LedgerDir: ledger,
	}
	sign := func(m enrollment.Manifest) ([]byte, []byte) {
		payload, err := json.Marshal(m)
		require.NoError(t, err)
		return signed(t, authority, "fabric-pq/enrollment/v1\x00", m),
			signed(t, authority, "fabric-pq/enrollment-history/v1\x00", enrollment.History{
				Network: m.Network, Node: m.Node, Generation: m.Generation,
				ProtectedEver: true, ManifestDigest: fmt.Sprintf("%x", sha256.Sum256(payload)),
			})
	}
	manifestBytes, historyBytes := sign(manifest)
	write(evidence+"/manifest.json", manifestBytes, 0o644)
	write(evidence+"/history.json", historyBytes, 0o644)
	run(staging+"/scripts/install-pq-managed-service.sh", staging+"/pq-launcher")
	t.Cleanup(func() {
		if t.Failed() {
			log, _ := exec.Command("journalctl", "--no-pager", "-u", unit, "-n", "100").CombinedOutput()
			t.Logf("managed unit journal:\n%s", log)
		}
		_ = exec.Command("systemctl", "stop", unit).Run()
	})
	run("systemd-analyze", "verify", unitPath)
	require.Equal(t, unitPath, run("systemctl", "show", unit, "--property=FragmentPath", "--value"))
	require.Equal(t, "fabric-pq", run("systemctl", "show", unit, "--property=User", "--value"))
	require.Empty(t, run("systemctl", "show", unit, "--property=DropInPaths", "--value"))
	require.Contains(t, run("systemctl", "show", unit, "--property=ExecStart", "--value"), installRoot+"/pq-launcher")

	checked := map[string]bool{}
	for _, path := range []string{
		unitPath,
		installRoot + "/pq-launcher",
		manifest.Executable,
		evidence + "/authority.pub",
		evidence + "/policy.pub",
		evidence + "/manifest.json",
		evidence + "/history.json",
		config + "/orderer.yaml",
		config + "/tls.key",
	} {
		require.Equal(t, path, run("realpath", "-e", path))
		for current := path; !checked[current]; current = filepath.Dir(current) {
			checked[current] = true
			info, err := os.Stat(current)
			require.NoError(t, err)
			require.Zero(t, info.Sys().(*syscall.Stat_t).Uid, current)
			require.Zero(t, info.Mode().Perm()&0o022, current)
			acl := run("getfacl", "-cp", current)
			require.NotRegexp(t, "(?m)^(user|group):[^:]+:|^default:", acl)
			run("runuser", "-u", "fabric-pq", "--", "test", "!", "-w", current)
		}
	}
	// Only the trusted system manager can install and launch a competing
	// system unit. Arbitrary code execution under the service UID is out of scope.
	output, err := exec.CommandContext(t.Context(), "runuser", "-u", "fabric-pq", "--", "systemd-run",
		"--system", "--no-ask-password", "--unit=fabric-pq-ci-alternate", "/usr/bin/true").CombinedOutput()
	require.Error(t, err, "service UID could register a competing system unit")
	require.Regexp(t, "(?i)(access denied|authentication required|not permitted)", string(output))

	cert, err := tls.X509KeyPair(clientKey.Cert, clientKey.Key)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(ca.CertBytes()))
	clientTLS := &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	transport := &http.Transport{TLSClientConfig: clientTLS}
	t.Cleanup(transport.CloseIdleConnections)
	startReady := func() {
		_ = exec.CommandContext(t.Context(), "systemctl", "reset-failed", unit).Run()
		run("systemctl", "start", unit)
		require.Eventually(t, func() bool {
			response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get("https://127.0.0.1:" + adminPort + "/participation/v1/channels/" + testfixture.ChannelID)
			if err != nil {
				return false
			}
			defer response.Body.Close()
			var status types.ChannelInfo
			return response.StatusCode == http.StatusOK && response.TLS.CurveID == tls.X25519MLKEM768 &&
				json.NewDecoder(response.Body).Decode(&status) == nil && status.Status == types.StatusActive
		}, 20*time.Second, 100*time.Millisecond)
		verifyManagedOperations(t, "127.0.0.1:"+opsPort, clientTLS)
		pid := run("systemctl", "show", unit, "--property=MainPID", "--value")
		require.Equal(t, manifest.Executable, run("readlink", "/proc/"+pid+"/exe"))
		process, err := os.Stat("/proc/" + pid)
		require.NoError(t, err)
		require.Equal(t, uint32(uid), process.Sys().(*syscall.Stat_t).Uid)
		namespaceOptions := func(path string) []string {
			return strings.Split(run("nsenter", "-t", pid, "-m", "--", "findmnt", "-n", "-o", "VFS-OPTIONS", "--target", path), ",")
		}
		require.Contains(t, namespaceOptions(evidence), "ro")
		require.Contains(t, namespaceOptions(installRoot), "ro")
		require.Contains(t, namespaceOptions(ledger), "rw")
	}
	stop := func() {
		transport.CloseIdleConnections()
		run("systemctl", "stop", unit)
	}
	reject := func(reason string) {
		t.Helper()
		// Type=exec may report success before the launcher finishes checking evidence.
		_ = exec.CommandContext(t.Context(), "systemctl", "reset-failed", unit).Run()
		_ = exec.CommandContext(t.Context(), "systemctl", "start", unit).Run()
		require.Eventually(t, func() bool {
			journal, err := exec.CommandContext(t.Context(), "journalctl", "--no-pager", "-u", unit, "-n", "60").Output()
			return err == nil && strings.Contains(string(journal), reason)
		}, 10*time.Second, 100*time.Millisecond, reason)
		for _, port := range []string{mainPort, adminPort, opsPort} {
			conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 300*time.Millisecond)
			if conn != nil {
				_ = conn.Close()
			}
			require.Error(t, err, "rejected startup opened port "+port)
		}
		stop()
	}
	startReady()
	stop()
	require.NoError(t, os.Remove(evidence+"/manifest.json"))
	reject("read enrollment manifest")
	write(evidence+"/manifest.json", manifestBytes, 0o644)

	next := manifest
	next.Generation++
	_, nextHistory := sign(next)
	write(evidence+"/history.json", nextHistory, 0o644)
	reject("manifest conflicts with protected enrollment history")

	baseline := enrollment.Manifest{Network: manifest.Network, Node: manifest.Node, Generation: 2, Mode: enrollment.Baseline, Executable: manifest.Executable, Arguments: manifest.Arguments}
	baselineManifest, baselineHistory := sign(baseline)
	write(evidence+"/manifest.json", baselineManifest, 0o644)
	write(evidence+"/history.json", baselineHistory, 0o644)
	reject("protected enrollment cannot return to baseline")

	write(evidence+"/manifest.json", manifestBytes, 0o644)
	write(evidence+"/history.json", historyBytes, 0o644)
	nonOperations, operations, ok := strings.Cut(ordinaryConfig, "Operations:")
	require.True(t, ok)
	insecure := nonOperations + "Operations:" + strings.Replace(operations, "Enabled: true", "Enabled: false", 1)
	write(config+"/orderer.yaml", []byte(insecure), 0o644)
	reject("protected HTTP listener requires TLS")
	write(config+"/orderer.yaml", []byte(ordinaryConfig), 0o644)
	startReady()
}
