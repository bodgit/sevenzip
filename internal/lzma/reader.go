package lzma

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

type readCloser struct {
	rc io.ReadCloser
	r  io.Reader
}

func (rc *readCloser) Close() error {
	return rc.rc.Close()
}

func (rc *readCloser) Read(p []byte) (int, error) {
	return rc.r.Read(p)
}

func NewReader(p []byte, s uint64, rc io.ReadCloser) (io.ReadCloser, error) {
	h := bytes.NewBuffer(p)
	_ = binary.Write(h, binary.LittleEndian, s)

	r, err := lzma.NewReader(io.MultiReader(h, rc))
	if err != nil {
		return nil, err
	}

	return &readCloser{
		rc: rc,
		r:  r,
	}, nil
}
