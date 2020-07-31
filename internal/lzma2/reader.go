package lzma2

import (
	"errors"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

type readCloser struct {
	c io.Closer
	r io.Reader
}

func (rc *readCloser) Close() error {
	var err error
	if rc.c != nil {
		err = rc.c.Close()
		rc.c, rc.r = nil, nil
	}
	return err
}

func (rc *readCloser) Read(p []byte) (int, error) {
	if rc.r == nil {
		return 0, errors.New("lzma2: Read after Close")
	}
	return rc.r.Read(p)
}

// NewReader returns a new LZMA io.ReadCloser.
func NewReader(_ []byte, _ uint64, readers ...io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, errors.New("lzma2: need exactly one reader")
	}

	lr, err := lzma.NewReader2(readers[0])
	if err != nil {
		return nil, err
	}

	return &readCloser{
		c: readers[0],
		r: lr,
	}, nil
}
