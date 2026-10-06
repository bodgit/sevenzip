package sevenzip

import (
	"bufio"
	"bytes"
	"io"
	"slices"
	"testing"
	"testing/iotest"

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

// shortReader returns at most one byte from each call to Read, as a
// bufio.Reader can at the end of its buffer, or a decompressor can when
// reading an encoded header.
type shortReader struct {
	io.Reader
	io.ByteReader
}

func newShortReader(b []byte) *shortReader {
	r := bytes.NewReader(b)

	return &shortReader{iotest.OneByteReader(r), r}
}

func TestReadCoder(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name       string
		coder      []byte
		id         []byte
		properties []byte
		wantErr    error
	}{
		{
			name:  "copy",
			coder: []byte{0x01, 0x00},
			id:    []byte{0x00},
		},
		{
			name:       "lzma",
			coder:      []byte{0x23, 0x03, 0x01, 0x01, 0x05, 0x5d, 0x00, 0x00, 0x10, 0x00},
			id:         []byte{0x03, 0x01, 0x01},
			properties: []byte{0x5d, 0x00, 0x00, 0x10, 0x00},
		},
		{
			name:    "truncated id",
			coder:   []byte{0x03, 0x03, 0x01},
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "truncated properties",
			coder:   []byte{0x23, 0x03, 0x01, 0x01, 0x05, 0x5d, 0x00},
			wantErr: io.ErrUnexpectedEOF,
		},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			c, err := readCoder(newShortReader(table.coder))

			if table.wantErr != nil {
				assert.ErrorIs(t, err, table.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, table.id, c.id)
			assert.Equal(t, table.properties, c.properties)
		})
	}
}

//nolint:funlen
func TestReadFilesInfo(t *testing.T) {
	t.Parallel()

	// A name property for a single file named "a", used to check parsing
	// carries on correctly after a skipped property.
	name := []byte{idName, 0x05, 0x00, 'a', 0x00, 0x00, 0x00}

	tables := []struct {
		name     string
		property []byte
		wantErr  error
	}{
		{
			name:     "dummy",
			property: []byte{idDummy, 0x02, 0x00, 0x00},
		},
		{
			name:     "anti",
			property: []byte{idAnti, 0x01, 0x80},
		},
		{
			name:     "comment",
			property: []byte{idComment, 0x03, 0x00, 'x', 0x00},
		},
		{
			name: "start position",
			// All defined, not external, one 64-bit value
			property: []byte{idStartPos, 0x0a, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
		{
			name:     "unknown",
			property: []byte{0x30, 0x02, 0xaa, 0xbb},
		},
		{
			name:     "empty stream and file",
			property: []byte{idEmptyStream, 0x01, 0x80, idEmptyFile, 0x01, 0x80},
		},
		{
			name: "modified time",
			// All defined, not external, one 64-bit time
			property: []byte{idMTime, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "attributes",
			// All defined, not external, one 32-bit value
			property: []byte{idWinAttributes, 0x06, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00},
		},
		{
			name:     "property longer than its data",
			property: []byte{idWinAttributes, 0x07, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00},
			wantErr:  errPropertyLength,
		},
		{
			name:     "property shorter than its data",
			property: []byte{idWinAttributes, 0x05, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00},
			wantErr:  io.ErrUnexpectedEOF,
		},
		{
			name:     "length too large",
			property: []byte{0x30, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			wantErr:  errUint64TooLarge,
		},
		{
			name:     "truncated",
			property: []byte{0x30, 0x7f, 0xaa},
			wantErr:  io.EOF,
		},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			b := slices.Concat([]byte{0x01}, table.property, name, []byte{idEnd})

			f, err := readFilesInfo(bufio.NewReader(bytes.NewReader(b)))

			if table.wantErr != nil {
				assert.ErrorIs(t, err, table.wantErr)

				return
			}

			require.NoError(t, err)
			require.Len(t, f.file, 1)
			assert.Equal(t, "a", f.file[0].Name)
		})
	}
}

func TestReadArchiveProperties(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name       string
		properties []byte
		wantErr    error
	}{
		{
			name:       "none",
			properties: []byte{idEnd},
		},
		{
			name:       "two",
			properties: []byte{0x20, 0x02, 0xaa, 0xbb, 0x21, 0x00, idEnd},
		},
		{
			name:       "length too large",
			properties: []byte{0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			wantErr:    errUint64TooLarge,
		},
		{
			name:       "truncated",
			properties: []byte{0x20, 0x7f, 0xaa},
			wantErr:    io.EOF,
		},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			// The archive properties are followed by a valid header
			// containing a single 10 byte file
			b := slices.Concat([]byte{idArchiveProperties}, table.properties,
				testHeader(slices.Concat(testPackInfo1, testUnpackInfo1), 1))

			h, err := readHeader(bufio.NewReader(bytes.NewReader(b)))

			if table.wantErr != nil {
				assert.ErrorIs(t, err, table.wantErr)

				return
			}

			require.NoError(t, err)
			require.Len(t, h.filesInfo.file, 1)
			assert.Equal(t, uint64(10), h.filesInfo.file[0].UncompressedSize)
		})
	}
}
