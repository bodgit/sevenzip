// Package lzma2 implements the LZMA2 decompressor.
package lzma2

import (
	"errors"
	"fmt"
	"io"

	"github.com/unxed/xz"
	"github.com/unxed/xz/lzma"
)

type seekReaderAt interface {
	io.ReaderAt
	io.Seeker
}

func streamSizeBySeeking(s io.Seeker) (int64, error) {
	curr, err := s.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, fmt.Errorf("seek current: %w", err)
	}

	size, err := s.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("seek end: %w", err)
	}

	_, err = s.Seek(curr, io.SeekStart)
	if err != nil {
		return size, fmt.Errorf("seek start: %w", err)
	}

	return size, nil
}

type readCloser struct {
	c io.Closer
	r io.Reader
}

var (
	errAlreadyClosed          = errors.New("lzma2: already closed")
	errNeedOneReader          = errors.New("lzma2: need exactly one reader")
	errInsufficientProperties = errors.New("lzma2: not enough properties")
	errInvalidProperties      = errors.New("lzma2: invalid properties")
)

func (rc *readCloser) Close() error {
	if rc.c == nil || rc.r == nil {
		return errAlreadyClosed
	}

	var errs []error

	// We close the reader from the xz library to return the buffers to the pool and stop the goroutines
	if closer, ok := rc.r.(io.Closer); ok {
		errs = append(errs, closer.Close())
	}

	errs = append(errs, rc.c.Close())

	rc.c, rc.r = nil, nil

	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("lzma2: error closing: %w", err)
	}

	return nil
}

func (rc *readCloser) Read(p []byte) (int, error) {
	if rc.r == nil {
		return 0, errAlreadyClosed
	}

	n, err := rc.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		err = fmt.Errorf("lzma2: error reading: %w", err)
	}

	return n, err
}

func tryParallelReader(config lzma.Reader2Config, readers []io.ReadCloser) (io.ReadCloser, bool) {
	sra, ok := readers[0].(seekReaderAt)
	if !ok {
		return nil, false
	}

	currentOffset, err := sra.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, false
	}

	size, err := streamSizeBySeeking(sra)
	if err != nil {
		return nil, false
	}

	var rAt io.ReaderAt = sra

	streamSize := size

	if currentOffset > 0 {
		rAt = io.NewSectionReader(sra, currentOffset, size-currentOffset)
		streamSize = size - currentOffset
	}

	// Use the parallel reader from github.com/unxed/xz
	pconfig := xz.ReaderConfig{DictCap: config.DictCap}

	pr, err := pconfig.NewParallelReader(rAt, streamSize)
	if err != nil {
		return nil, false
	}

	return &readCloser{
		c: readers[0],
		r: pr,
	}, true
}

// NewReader returns a new LZMA2 io.ReadCloser.
func NewReader(p []byte, _ uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, errNeedOneReader
	}

	if len(p) != 1 {
		return nil, errInsufficientProperties
	}

	if p[0] > 40 {
		return nil, errInvalidProperties
	}

	config := lzma.Reader2Config{
		DictCap: (2 | (int(p[0]) & 1)) << (p[0]/2 + 11), // This gem came from Lzma2Dec.c
	}

	if err := config.Verify(); err != nil {
		return nil, fmt.Errorf("lzma2: error verifying config: %w", err)
	}

	// Try parallel decompression if the input is seekable
	if pr, ok := tryParallelReader(config, readers); ok {
		return pr, nil
	}

	lr, err := config.NewReader2(readers[0])
	if err != nil {
		return nil, fmt.Errorf("lzma2: error creating reader: %w", err)
	}

	return &readCloser{
		c: readers[0],
		r: lr,
	}, nil
}
