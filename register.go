package sevenzip

import (
	"errors"
	"io"
	"sync"

	"github.com/bodgit/sevenzip/internal/aes7z"
	"github.com/bodgit/sevenzip/internal/bzip2"
	"github.com/bodgit/sevenzip/internal/deflate"
	"github.com/bodgit/sevenzip/internal/lzma"
	"github.com/bodgit/sevenzip/internal/lzma2"
)

// Decompressor describes the function signature that decompression/decryption
// methods must implement to return a new instance of themselves. They are
// passed any property bytes, the size of the stream and a varying number of,
// but nearly always one, io.ReadCloser providing the stream of bytes. Blame
// (currently unimplemented) BCJ2 for that one.
type Decompressor func([]byte, uint64, []io.ReadCloser) (io.ReadCloser, error)

var decompressors sync.Map

func init() {
	// Copy (just return the passed io.ReadCloser)
	RegisterDecompressor([]byte{0x00}, Decompressor(func(_ []byte, _ uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
		if len(readers) != 1 {
			return nil, errors.New("sevenzip: need exactly one reader")
		}
		return readers[0], nil
	}))
	// LZMA
	RegisterDecompressor([]byte{0x03, 0x01, 0x01}, Decompressor(lzma.NewReader))
	// Deflate
	RegisterDecompressor([]byte{0x04, 0x01, 0x08}, Decompressor(deflate.NewReader))
	// Bzip2
	RegisterDecompressor([]byte{0x04, 0x02, 0x02}, Decompressor(bzip2.NewReader))
	// AES-CBC-256 & SHA-256
	RegisterDecompressor([]byte{0x06, 0xf1, 0x07, 0x01}, Decompressor(aes7z.NewReader))
	// LZMA2
	RegisterDecompressor([]byte{0x21}, Decompressor(lzma2.NewReader))
}

// RegisterDecompressor allows custom decompressors for a specified method ID.
func RegisterDecompressor(method []byte, dcomp Decompressor) {
	if _, dup := decompressors.LoadOrStore(string(method), dcomp); dup {
		panic("decompressor already registered")
	}
}

func decompressor(method []byte) Decompressor {
	di, ok := decompressors.Load(string(method))
	if !ok {
		return nil
	}
	return di.(Decompressor)
}
