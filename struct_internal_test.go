package sevenzip

import (
	"bufio"
	"bytes"
	"io"
	"math"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileReadCloser_Seek(t *testing.T) {
	t.Parallel()

	r, err := OpenReader(filepath.Join("testdata", "t0.7z"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err = r.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	require.GreaterOrEqual(t, len(r.File), 1)

	rc, _, _, err := r.folderReader(r.si, r.File[0].folder)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err = rc.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	_, err = rc.Seek(0, math.MaxInt)
	assert.Equal(t, err, errInvalidWhence)

	_, err = rc.Seek(-1, io.SeekStart)
	assert.Equal(t, err, errNegativeSeek)

	n, err := rc.Seek(1, io.SeekCurrent)
	assert.Equal(t, int64(1), n)
	assert.NoError(t, err) //nolint:testifylint

	_, err = rc.Seek(-1, io.SeekCurrent)
	assert.Equal(t, err, errSeekBackwards)

	_, err = rc.Seek(int64(r.File[0].UncompressedSize), io.SeekCurrent) //nolint:gosec
	assert.Equal(t, err, errSeekEOF)

	n, err = rc.Seek(int64(r.File[0].UncompressedSize), io.SeekStart) //nolint:gosec
	assert.Equal(t, n, int64(r.File[0].UncompressedSize))             //nolint:gosec
	assert.NoError(t, err)                                            //nolint:testifylint

	n, err = rc.Seek(0, io.SeekEnd)
	assert.Equal(t, n, int64(r.File[0].UncompressedSize)) //nolint:gosec
	assert.NoError(t, err)
}

//nolint:funlen
func TestFolderReader(t *testing.T) {
	t.Parallel()

	var (
		// One packed stream of 10 bytes.
		packInfo1 = []byte{idPackInfo, 0x00, 0x01, idSize, 0x0a, idEnd}
		// Two packed streams of 10 bytes each.
		packInfo2 = []byte{idPackInfo, 0x00, 0x02, idSize, 0x0a, 0x0a, idEnd}
		// One folder with a single copy coder, unpacking to 10 bytes.
		unpackInfo1 = []byte{
			idUnpackInfo, idFolder, 0x01, 0x00,
			0x01, 0x01, 0x00,
			idCodersUnpackSize, 0x0a, idEnd,
		}
	)

	tables := []struct {
		name        string
		streamsInfo []byte
		wantErr     error
	}{
		{
			name:        "valid",
			streamsInfo: slices.Concat(packInfo1, unpackInfo1),
		},
		{
			name:        "missing pack info",
			streamsInfo: unpackInfo1,
			wantErr:     errMissingPackInfo,
		},
		{
			name:        "missing pack sizes",
			streamsInfo: slices.Concat([]byte{idPackInfo, 0x00, 0x01, idEnd}, unpackInfo1),
			wantErr:     errMissingPackInfo,
		},
		{
			name: "too few pack streams",
			streamsInfo: slices.Concat(packInfo1, []byte{
				idUnpackInfo, idFolder, 0x02, 0x00,
				0x01, 0x01, 0x00,
				0x01, 0x01, 0x00,
				idCodersUnpackSize, 0x0a, 0x0a, idEnd,
			}),
			wantErr: errPackStreamMismatch,
		},
		{
			name:        "too many pack streams",
			streamsInfo: slices.Concat(packInfo2, unpackInfo1),
			wantErr:     errPackStreamMismatch,
		},
		{
			name: "bind pair output out of range",
			streamsInfo: slices.Concat(packInfo1, []byte{
				idUnpackInfo, idFolder, 0x01, 0x00,
				0x02, 0x01, 0x00, 0x01, 0x00,
				0x00, 0x05, // in 0, out 5
				idCodersUnpackSize, 0x0a, 0x0a, idEnd,
			}),
			wantErr: errInvalidBindPair,
		},
		{
			name: "bind pair input out of range",
			streamsInfo: slices.Concat(packInfo2, []byte{
				idUnpackInfo, idFolder, 0x01, 0x00,
				0x02, 0x01, 0x00, 0x01, 0x00,
				0x05, 0x00, // in 5, out 0
				idCodersUnpackSize, 0x0a, 0x0a, idEnd,
			}),
			wantErr: errInvalidBindPair,
		},
		{
			name: "packed stream out of range",
			streamsInfo: slices.Concat(packInfo2, []byte{
				idUnpackInfo, idFolder, 0x01, 0x00,
				0x01, 0x11, 0x00, 0x02, 0x01, // 2 in, 1 out
				0x00, 0x07, // packed streams 0 and 7
				idCodersUnpackSize, 0x0a, idEnd,
			}),
			wantErr: errInvalidPackedStream,
		},
	}

	data := []byte("0123456789abcdefghij")

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			b := slices.Concat([]byte{idMainStreamsInfo}, table.streamsInfo, []byte{idEnd})[1:]

			si, err := readStreamsInfo(bufio.NewReader(bytes.NewReader(b)))
			if err == nil {
				for i := range si.Folders() {
					var rc *folderReadCloser

					if rc, _, _, err = si.folderReader(bytes.NewReader(data), i, ""); err != nil {
						break
					}

					var got []byte

					got, err = io.ReadAll(rc)
					require.NoError(t, err)
					require.NoError(t, rc.Close())
					assert.Equal(t, data[:10], got)
				}
			}

			if table.wantErr != nil {
				assert.ErrorIs(t, err, table.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReadCloserClosePool(t *testing.T) {
	t.Parallel()

	r, err := OpenReader(filepath.Join("testdata", "lzma1900.7z"))
	require.NoError(t, err)

	// Find two non-empty files in the same stream
	var f1, f2 *File

	seen := make(map[int]*File)

	for _, f := range r.File {
		if f.UncompressedSize == 0 {
			continue
		}

		if prev, ok := seen[f.Stream]; ok {
			f1, f2 = prev, f

			break
		}

		seen[f.Stream] = f
	}

	require.NotNil(t, f2)

	// Open the later file first so it doesn't reuse the pooled reader
	rc2, err := f2.Open()
	require.NoError(t, err)

	_, err = io.ReadFull(rc2, make([]byte, 1))
	require.NoError(t, err)

	// Partially read the earlier file, closing it adds its reader to the pool
	rc1, err := f1.Open()
	require.NoError(t, err)

	_, err = io.ReadFull(rc1, make([]byte, 1))
	require.NoError(t, err)
	require.NoError(t, rc1.Close())

	require.NoError(t, r.Close())

	// Closing the archive should close and empty the pool
	_, ok := r.pool[f1.folder].Get(f1.offset + 1)
	assert.False(t, ok)

	// Closing a file after the archive shouldn't add its reader to the pool
	require.NoError(t, rc2.Close())

	_, ok = r.pool[f2.folder].Get(f2.offset + 1)
	assert.False(t, ok)
}
