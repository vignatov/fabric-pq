/*
SPDX-License-Identifier: Apache-2.0
*/

// Package activation authenticates and durably reconciles local channel activation.
package activation

import (
	"bytes"
	"crypto/mldsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hyperledger/fabric/internal/pkg/pqtransport"
)

type signedDocument struct {
	Payload   []byte
	Signature []byte
}

// AuthenticateRegistry reads the active checkpoint and validates its policy
// before returning channel membership. It does not reconcile the ledger or
// open admission; each channel must still complete its normal recovery.
func (s *Store) AuthenticateRegistry(signer *mldsa.PublicKey, network, node string) (*pqtransport.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, err := readRecord[checkpoint](s.dir, "checkpoint")
	if err != nil {
		return nil, fmt.Errorf("read protected checkpoint: %w", err)
	}
	policy, err := pqtransport.Authenticate(current.Policy.Payload, current.Policy.Signature, signer, &current.Checkpoint, network, node)
	if err != nil {
		return nil, fmt.Errorf("authenticate protected checkpoint: %w", err)
	}
	channels, err := policy.Channels()
	if err != nil {
		return nil, err
	}
	for id := range current.Blocks {
		if _, ok := channels[id]; !ok {
			return nil, fmt.Errorf("checkpoint contains unbound channel %q", id)
		}
	}
	journal, err := s.readJournal()
	if err != nil {
		return nil, fmt.Errorf("read activation journal: %w", err)
	}
	if journal.Channel != "" {
		if _, ok := channels[journal.Channel]; !ok {
			return nil, errors.New("activation journal contains an unbound channel")
		}
	}
	if _, err := readRecord[string](s.dir, nodeQuarantine); err == nil {
		return nil, errors.New("protected node is quarantined")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read node quarantine: %w", err)
	}
	// Durable channel records use hashed names. Reject any record that no
	// longer corresponds to an authenticated binding, including quarantines.
	known := make(map[string]bool, len(channels))
	for id := range channels {
		known[digest([]byte(id))] = true
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		name := entry.Name()
		var hash string
		switch {
		case strings.HasPrefix(name, "genesis-"):
			hash = strings.TrimSuffix(strings.TrimPrefix(name, "genesis-"), ".block")
		case strings.HasPrefix(name, "join-orderer-"):
			hash = strings.TrimPrefix(name, "join-orderer-")
		case strings.HasPrefix(name, "join-peer-"):
			hash = strings.TrimSuffix(strings.TrimPrefix(name, "join-peer-"), ".block")
		case strings.HasPrefix(name, "quarantine-") && name != nodeQuarantine:
			hash = strings.TrimPrefix(name, "quarantine-")
		case strings.HasPrefix(name, "approval-"):
			hash, _, _ = strings.Cut(strings.TrimPrefix(name, "approval-"), "-")
		default:
			continue
		}
		if !known[hash] {
			return nil, fmt.Errorf("protected state %q has no authenticated channel binding", name)
		}
	}
	return policy, nil
}

type checkpoint struct {
	pqtransport.Checkpoint
	Policy signedDocument
	Blocks map[string]blockIdentity `json:",omitempty"`
}

type phase string

const (
	prepared      phase = "PREPARED"
	commitPending phase = "COMMIT_PENDING"
	active        phase = "ACTIVE"
	aborted       phase = "ABORTED"
)

type journal struct {
	Phase     phase
	Channel   string
	Base      blockIdentity
	Block     blockIdentity
	Previous  checkpoint
	Next      checkpoint
	Operation signedDocument
}

// Store serializes a node's checkpoint transitions. Each protected directory
// has one owning process and one Store instance in the proof.
type Store struct {
	dir   string
	mu    sync.Mutex
	hit   func(string)
	gates map[string]*Gate
}

// OpenStore opens operator-provisioned state. The optional probe is used for
// test interruption at individual persistence and publication boundaries.
func OpenStore(dir string, probe func(string)) (*Store, error) {
	if err := SyncDirectory(dir); err != nil {
		return nil, err
	}
	return &Store{dir: dir, hit: probe, gates: make(map[string]*Gate)}, nil
}

// Provision installs the initial operator-provided checkpoint in an empty
// store. Recover authenticates its policy against the independent trust anchor.
func (s *Store) Provision(initial pqtransport.Checkpoint, payload, signature []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := readRecord[checkpoint](s.dir, "checkpoint")
	if err == nil {
		return errors.New("checkpoint already exists")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing checkpoint: %w", err)
	}
	return s.write("checkpoint", checkpoint{Checkpoint: initial, Policy: signedDocument{payload, signature}})
}

func (s *Store) probe(boundary string) {
	if s.hit != nil {
		s.hit(boundary)
	}
}

func (s *Store) closeGates() {
	var draining []*generation
	for _, gate := range s.gates {
		if current := gate.stop(); current != nil {
			draining = append(draining, current)
		}
	}
	for _, current := range draining {
		current.work.Wait()
	}
}

func readRecord[T any](dir, name string) (T, error) {
	var record T
	payload, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return record, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("decode %s: %w", name, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return record, fmt.Errorf("unexpected trailing data in %s", name)
	}
	return record, nil
}

func (s *Store) write(name string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(s.dir, ".activation-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(payload)
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	s.probe(name + ":file-synced")
	if err := os.Rename(file.Name(), filepath.Join(s.dir, name)); err != nil {
		return err
	}
	s.probe(name + ":renamed")
	if err := SyncDirectory(s.dir); err != nil {
		return err
	}
	s.probe(name + ":durable")
	return nil
}

// SyncDirectory flushes directory entries on the proof's local Linux store.
func SyncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
