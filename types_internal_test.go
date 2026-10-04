package sevenzip

import (
	"bufio"
	"bytes"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:gochecknoglobals
var (
	// One packed stream of 10 bytes.
	testPackInfo1 = []byte{idPackInfo, 0x00, 0x01, idSize, 0x0a, idEnd}
	// One folder with a single copy coder, unpacking to 10 bytes.
	testUnpackInfo1 = []byte{
		idUnpackInfo, idFolder, 0x01, 0x00,
		0x01, 0x01, 0x00,
		idCodersUnpackSize, 0x0a, idEnd,
	}
	// Two packed streams of 10 and 20 bytes.
	testPackInfo2 = []byte{idPackInfo, 0x00, 0x02, idSize, 0x0a, 0x14, idEnd}
	// Two folders, each with a single copy coder, unpacking to 10 and 20
	// bytes respectively.
	testUnpackInfo2 = []byte{
		idUnpackInfo, idFolder, 0x02, 0x00,
		0x01, 0x01, 0x00,
		0x01, 0x01, 0x00,
		idCodersUnpackSize, 0x0a, 0x14, idEnd,
	}
)

func testHeader(streamsInfo []byte, files byte) []byte {
	var h []byte

	if streamsInfo != nil {
		h = slices.Concat([]byte{idMainStreamsInfo}, streamsInfo, []byte{idEnd})
	}

	return slices.Concat(h, []byte{idFilesInfo, files, idEnd, idEnd})
}

//nolint:funlen
func TestReadHeader(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name    string
		header  []byte
		sizes   []uint64
		wantErr error
	}{
		{
			name:   "one file per folder without substreams",
			header: testHeader(slices.Concat(testPackInfo2, testUnpackInfo2), 2),
			sizes:  []uint64{10, 20},
		},
		{
			name: "two files in one folder",
			header: testHeader(slices.Concat(testPackInfo1, testUnpackInfo1, []byte{
				idSubStreamsInfo, idNumUnpackStream, 0x02, idSize, 0x04, idEnd,
			}), 2),
			sizes: []uint64{4, 6},
		},
		{
			name:    "files without streams info",
			header:  testHeader(nil, 1),
			wantErr: errStreamMismatch,
		},
		{
			name:    "files without unpack info",
			header:  testHeader([]byte{}, 1),
			wantErr: errStreamMismatch,
		},
		{
			name:    "more files than folders",
			header:  testHeader(slices.Concat(testPackInfo1, testUnpackInfo1), 2),
			wantErr: errStreamMismatch,
		},
		{
			name:    "fewer files than folders",
			header:  testHeader(slices.Concat(testPackInfo2, testUnpackInfo2), 1),
			wantErr: errStreamMismatch,
		},
		{
			name: "more files than substreams",
			header: testHeader(slices.Concat(testPackInfo1, testUnpackInfo1, []byte{
				idSubStreamsInfo, idNumUnpackStream, 0x02, idSize, 0x04, idEnd,
			}), 3),
			wantErr: errStreamMismatch,
		},
		{
			name: "substreams without sizes",
			header: testHeader(slices.Concat(testPackInfo1, testUnpackInfo1, []byte{
				idSubStreamsInfo, idNumUnpackStream, 0x02, idEnd,
			}), 2),
			wantErr: errMissingSubStreamSizes,
		},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			h, err := readHeader(bufio.NewReader(bytes.NewReader(table.header)))

			if table.wantErr != nil {
				assert.ErrorIs(t, err, table.wantErr)

				return
			}

			require.NoError(t, err)

			sizes := make([]uint64, 0, len(h.filesInfo.file))
			for _, f := range h.filesInfo.file {
				sizes = append(sizes, f.UncompressedSize)
			}

			assert.Equal(t, table.sizes, sizes)
		})
	}
}

// TestNewReaderIssue491 is the reproducer from
// https://github.com/bodgit/sevenzip/issues/491, a header declaring files
// with streams but with no unpack info to describe them.
func TestNewReaderIssue491(t *testing.T) {
	t.Parallel()

	data := []byte("7z\xbc\xaf'\x1c00\xb8\xe7\xedw\x10\x00\x00\x00\x00\x00\x00\x00j\x00\x00\x00\x00\x00\x00\x00\xa3\x15\xc6V0000000000000000\x01\x04\x00\x05\xa40\x00\x00") //nolint:lll

	_, err := NewReader(bytes.NewReader(data), int64(len(data)))
	assert.ErrorIs(t, err, errStreamMismatch)
}
