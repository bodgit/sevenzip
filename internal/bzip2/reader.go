package bzip2

import (
	"compress/bzip2"
	"io"
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

func NewReader(_ []byte, _ uint64, rc io.ReadCloser) (io.ReadCloser, error) {
	return &readCloser{
		rc: rc,
		r:  bzip2.NewReader(rc),
	}, nil
}
