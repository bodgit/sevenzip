package sevenzip

import (
	"io"
	"sync"

	"github.com/bodgit/sevenzip/internal/aes7z"
	"github.com/bodgit/sevenzip/internal/bzip2"
	"github.com/bodgit/sevenzip/internal/lzma"
)

type Decompressor func([]byte, uint64, io.ReadCloser) (io.ReadCloser, error)

var decompressors sync.Map

func init() {
	// Copy (just return the passed io.ReadCloser)
	RegisterDecompressor([]byte{0x00}, Decompressor(func(_ []byte, _ uint64, rc io.ReadCloser) (io.ReadCloser, error) {
		return rc, nil
	}))
	// LZMA
	RegisterDecompressor([]byte{0x03, 0x01, 0x01}, Decompressor(lzma.NewReader))
	// Bzip2
	RegisterDecompressor([]byte{0x04, 0x02, 0x02}, Decompressor(bzip2.NewReader))
	// AES-CBC-256 & SHA-256
	RegisterDecompressor([]byte{0x06, 0xf1, 0x07, 0x01}, Decompressor(aes7z.NewReader))
}

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
