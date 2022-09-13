package ppmd

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/stangelandcl/ppmd"
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
		return 0, errors.New("ppmd: Read after Close")
	}

	return rc.r.Read(p)
}

// NewReader returns a new PPMD io.ReadCloser.
func NewReader(p []byte, uncompressedSize uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, errors.New("ppmd: need exactly one reader")
	}

	if len(p) != 5 {
		return nil, errors.New("ppmd: needs exactly five property bytes")
	}

	order := p[0]
	memory := binary.LittleEndian.Uint32(p[1:])

	pr, err := ppmd.NewH7zReader(readers[0], int(order), int(memory), int(uncompressedSize))
	if err != nil {
		return nil, err
	}

	return &readCloser{
		c: readers[0],
		r: &pr,
	}, nil
}
