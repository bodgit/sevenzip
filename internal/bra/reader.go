package bra

import (
	"bytes"
	"errors"
	"io"
)

type readCloser struct {
	rc   io.ReadCloser
	buf  bytes.Buffer
	n    int
	conv converter
}

func (rc *readCloser) Close() (err error) {
	if rc.rc != nil {
		err = rc.rc.Close()
		rc.rc = nil
	}

	return
}

func (rc *readCloser) Read(p []byte) (int, error) {
	if rc.rc == nil {
		return 0, errors.New("bra: Read after Close")
	}

	if _, err := io.CopyN(&rc.buf, rc.rc, int64(max(len(p), rc.conv.Size())-rc.buf.Len())); err != nil {
		if !errors.Is(err, io.EOF) {
			return 0, err
		}

		if rc.buf.Len() < rc.conv.Size() {
			rc.n = rc.buf.Len()
		}
	}

	rc.n += rc.conv.Convert(rc.buf.Bytes()[rc.n:], false)

	n, err := rc.buf.Read(p[:min(rc.n, len(p))])

	rc.n -= n

	return n, err
}

func newReader(readers []io.ReadCloser, conv converter) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, errors.New("bra: need exactly one reader")
	}

	return &readCloser{
		rc:   readers[0],
		conv: conv,
	}, nil
}
