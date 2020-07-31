package deflate

import (
	"compress/flate"
	"errors"
	"io"
	"sync"
)

var flateReaderPool sync.Pool

type readCloser struct {
	c  io.Closer
	fr io.ReadCloser
	mu sync.Mutex
}

func (rc *readCloser) Close() error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	var err error
	if rc.c != nil {
		if err = rc.fr.Close(); err != nil {
			return err
		}
		flateReaderPool.Put(rc.fr)
		err = rc.c.Close()
		rc.c, rc.fr = nil, nil
	}
	return err
}

func (rc *readCloser) Read(p []byte) (int, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.fr == nil {
		return 0, errors.New("deflate: Read after Close")
	}
	return rc.fr.Read(p)
}

// NewReader returns a new DEFLATE io.ReadCloser.
func NewReader(_ []byte, _ uint64, readers ...io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, errors.New("deflate: need exactly one reader")
	}

	fr, ok := flateReaderPool.Get().(io.ReadCloser)
	if ok {
		fr.(flate.Resetter).Reset(readers[0], nil)
	} else {
		fr = flate.NewReader(readers[0])
	}

	return &readCloser{
		c:  readers[0],
		fr: fr,
	}, nil
}
