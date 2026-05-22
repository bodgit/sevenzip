//nolint:paralleltest,testpackage
package lzma2

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type dummyReadCloser struct {
	io.Reader
}

func (d dummyReadCloser) Close() error {
	return nil
}

func TestNewReader(t *testing.T) {
	// Test too many/few readers
	_, err := NewReader([]byte{0}, 0, nil)
	if !errors.Is(err, errNeedOneReader) {
		t.Errorf("expected errNeedOneReader, got %v", err)
	}

	// Test invalid property length
	_, err = NewReader([]byte{}, 0, []io.ReadCloser{dummyReadCloser{bytes.NewReader(nil)}})
	if !errors.Is(err, errInsufficientProperties) {
		t.Errorf("expected errInsufficientProperties, got %v", err)
	}

	// Test invalid property byte (> 40)
	_, err = NewReader([]byte{41}, 0, []io.ReadCloser{dummyReadCloser{bytes.NewReader(nil)}})
	if !errors.Is(err, errInvalidProperties) {
		t.Errorf("expected errInvalidProperties, got %v", err)
	}

	// Test valid property byte (<= 40)
	// Any value <= 40 should pass the property byte check
	_, err = NewReader([]byte{0}, 0, []io.ReadCloser{dummyReadCloser{bytes.NewReader(nil)}})
	if errors.Is(err, errInvalidProperties) {
		t.Errorf("unexpected errInvalidProperties for valid property, got %v", err)
	}
}
