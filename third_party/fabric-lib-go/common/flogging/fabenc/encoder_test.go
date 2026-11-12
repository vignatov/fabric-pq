/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabenc_test

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/common/flogging/fabenc"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestEncodeEntry(t *testing.T) {
	startTime := time.Now()
	tests := []struct {
		name     string
		spec     string
		fields   []zapcore.Field
		expected string
	}{
		{name: "empty spec and nil fields", spec: "", fields: nil, expected: "\n"},
		{name: "empty spec with fields", spec: "", fields: []zapcore.Field{zap.String("key", "value")}, expected: "key=value\n"},
		{name: "simple spec and nil fields", spec: "simple-string", expected: "simple-string\n"},
		{name: "simple spec and empty fields", spec: "simple-string", fields: []zapcore.Field{}, expected: "simple-string\n"},
		{name: "simple spec with fields", spec: "simple-string", fields: []zapcore.Field{zap.String("key", "value")}, expected: "simple-string key=value\n"},
		{name: "duration", spec: "", fields: []zapcore.Field{zap.Duration("duration", time.Second)}, expected: "duration=1s\n"},
		{name: "time", spec: "", fields: []zapcore.Field{zap.Time("time", startTime)}, expected: fmt.Sprintf("time=%s\n", startTime.Format("2006-01-02T15:04:05.999Z07:00"))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			formatters, err := fabenc.ParseFormat(tc.spec)
			require.NoError(t, err)

			enc := fabenc.NewFormatEncoder(formatters...)

			pc, file, l, ok := runtime.Caller(0)
			line, err := enc.EncodeEntry(
				zapcore.Entry{
					// The entry information should be completely omitted
					Level:      zapcore.InfoLevel,
					Time:       startTime,
					LoggerName: "logger-name",
					Message:    "message",
					Caller:     zapcore.NewEntryCaller(pc, file, l, ok),
					Stack:      "stack",
				},
				tc.fields,
			)
			require.NoError(t, err)
			require.Equal(t, tc.expected, line.String())
		})
	}
}

func TestEncodeFieldsFailed(t *testing.T) {
	enc := fabenc.NewFormatEncoder()
	// A key that reduces to nothing once invalid runes are stripped cannot be
	// encoded as logfmt, so EncodeEntry surfaces the error.
	_, err := enc.EncodeEntry(zapcore.Entry{}, []zapcore.Field{zap.String(" ", "value")})
	require.Error(t, err)
}

// TestEncodeEntryPreservesOrder verifies that an entry's own fields are emitted
// in insertion order rather than sorted by key.
func TestEncodeEntryPreservesOrder(t *testing.T) {
	enc := fabenc.NewFormatEncoder()
	line, err := enc.EncodeEntry(zapcore.Entry{}, []zapcore.Field{
		zap.String("zebra", "z"),
		zap.Int("apple", 1),
		zap.String("mango", "m"),
	})
	require.NoError(t, err)
	require.Equal(t, "zebra=z apple=1 mango=m\n", line.String())
}

// TestEncodeEntryPreservesDuplicateKeys verifies that repeated keys are not
// merged: each occurrence is emitted with its own value. The With context is
// emitted (sorted) before the entry's fields, and a key present in both the
// context and the entry appears in each.
func TestEncodeEntryPreservesDuplicateKeys(t *testing.T) {
	enc := fabenc.NewFormatEncoder()
	enc.Fields["ctx"] = "c" // With context
	enc.Fields["dup"] = "from-with"

	line, err := enc.EncodeEntry(zapcore.Entry{}, []zapcore.Field{
		zap.String("dup", "from-field"), // same key as the context entry
		zap.String("zzz", "z"),
		zap.String("zzz", "z2"), // duplicated within the entry
	})
	require.NoError(t, err)
	require.Equal(t, "ctx=c dup=from-with dup=from-field zzz=z zzz=z2\n", line.String())
}

// TestEncodeEntrySkipsValuelessFields verifies that a field which adds no value
// under its key (e.g. zap.Skip, whose key is empty) is dropped rather than
// emitted as an invalid key.
func TestEncodeEntrySkipsValuelessFields(t *testing.T) {
	enc := fabenc.NewFormatEncoder()
	line, err := enc.EncodeEntry(zapcore.Entry{}, []zapcore.Field{
		zap.Skip(),
		zap.String("k", "v"),
		zap.Skip(),
	})
	require.NoError(t, err)
	require.Equal(t, "k=v\n", line.String())
}

func TestFormatEncoderClone(t *testing.T) {
	enc := fabenc.NewFormatEncoder()
	cloned := enc.Clone()
	require.Equal(t, enc, cloned)
}
