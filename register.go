package sevenzip

import (
	"bytes"
	"compress/bzip2"
	"encoding/binary"
	"io"
	"sync"

	"github.com/bodgit/sevenzip/internal/aes7z"
	"github.com/ulikunitz/xz/lzma"
)

type Decompressor func([]byte, uint64, io.Reader) (io.Reader, error)

var decompressors sync.Map

func init() {
	// Copy
	RegisterDecompressor([]byte{0x00}, Decompressor(func(_ []byte, _ uint64, r io.Reader) (io.Reader, error) {
		return r, nil
	}))
	// LZMA
	RegisterDecompressor([]byte{0x03, 0x01, 0x01}, Decompressor(func(p []byte, s uint64, r io.Reader) (io.Reader, error) {
		h := bytes.NewBuffer(p)
		_ = binary.Write(h, binary.LittleEndian, s)
		return lzma.NewReader(io.MultiReader(h, r))
	}))
	// Bzip2
	RegisterDecompressor([]byte{0x04, 0x02, 0x02}, Decompressor(func(_ []byte, _ uint64, r io.Reader) (io.Reader, error) {
		return bzip2.NewReader(r), nil
	}))
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
