// Package ppmd implements the PPMD filter.
package ppmd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/stangelandcl/ppmd"
)

var (
	errAlreadyClosed          = errors.New("ppmd: already closed")
	errNeedOneReader          = errors.New("ppmd: need exactly one reader")
	errInsufficientProperties = errors.New("ppmd: not enough properties")
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

	if err != nil {
		return fmt.Errorf("ppmd: error closing: %w", err)
	}

	return nil
}

func (rc *readCloser) Read(p []byte) (int, error) {
	if rc.r == nil {
		return 0, errAlreadyClosed
	}

	n, err := rc.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		err = fmt.Errorf("ppmd: error reading: %w", err)
	}

	return n, err
}

// NewReader returns a new PPMD io.ReadCloser.
func NewReader(p []byte, uncompressedSize uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, errNeedOneReader
	}

	if len(p) != 5 {
		return nil, errInsufficientProperties
	}

	order := p[0]
	memory := binary.LittleEndian.Uint32(p[1:])

	pr, err := ppmd.NewH7zReader(readers[0], int(order), int(memory), int(uncompressedSize)) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("ppmd: error creating reader: %w", err)
	}

	return &readCloser{
		c: readers[0],
		r: &pr,
	}, nil
}
