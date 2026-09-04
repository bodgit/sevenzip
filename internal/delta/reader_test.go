package delta

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The property byte holds distance-1, so 0xff is a distance of 256.
func TestNewReaderDistance(t *testing.T) {
	t.Parallel()

	for _, table := range []struct {
		name     string
		property byte
		want     int
	}{
		{"minimum", 0x00, 1},
		{"maximum", 0xff, 256},
	} {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			src := make([]byte, 512)
			for i := range src {
				src[i] = byte(i)
			}

			rc, err := NewReader([]byte{table.property}, 0, []io.ReadCloser{
				io.NopCloser(bytes.NewReader(src)),
			})
			require.NoError(t, err)

			defer rc.Close()

			assert.Equal(t, table.want, rc.(*readCloser).delta)

			// A distance the filter cannot represent leaves Read spinning.
			p := make([]byte, len(src))
			n, err := rc.Read(p)
			require.NoError(t, err)
			assert.Equal(t, len(src), n)
		})
	}
}
