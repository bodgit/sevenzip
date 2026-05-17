package aes7z_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/bodgit/sevenzip/internal/aes7z"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// passwordSetter matches the Password method on the AES reader without
// importing the parent package (which would be circular).
type passwordSetter interface {
	Password(p string) error
}

func TestPassword(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name    string
		cycles  byte
		wantErr error
	}{
		{
			name:   "low cycles (0)",
			cycles: 0,
		},
		{
			name:   "standard cycles (19)",
			cycles: 19,
		},
		{
			name:   "at cap (24)",
			cycles: 24,
		},
		{
			name:    "one above cap (25)",
			cycles:  25,
			wantErr: aes7z.ErrCyclesPowerTooLarge,
		},
		{
			name:    "high cycles (62)",
			cycles:  62,
			wantErr: aes7z.ErrCyclesPowerTooLarge,
		},
		{
			name:   "raw mode (0x3f, no hashing)",
			cycles: 0x3f,
		},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			p := []byte{0x80 | table.cycles, 0x00, 0x00}
			rc, err := aes7z.NewReader(p, 0, []io.ReadCloser{io.NopCloser(bytes.NewReader(nil))})
			require.NoError(t, err)

			defer func() {
				require.NoError(t, rc.Close())
			}()

			ps, ok := rc.(passwordSetter)
			require.True(t, ok)

			err = ps.Password("password")

			if table.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, table.wantErr)
			}
		})
	}
}
