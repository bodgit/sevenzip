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
type mockSeekReaderAt struct {
	io.Reader
}

func (m mockSeekReaderAt) ReadAt(p []byte, off int64) (n int, err error) { return 0, io.EOF }
func (m mockSeekReaderAt) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekEnd {
		return 100, nil // Simulate the presence of an end for the ParallelReader trigger
	}
	return 0, nil
}

func TestNewReader_InterfaceLogic(t *testing.T) {
	// 1. Test with the standard Reader (should select NewReader2)
	p := []byte{0} // Properties
	r1 := dummyReadCloser{bytes.NewReader([]byte{0, 0, 0, 0, 0})}
	rc1, err := NewReader(p, 0, []io.ReadCloser{r1})
	if err != nil {
		t.Fatalf("Failed to create basic reader: %v", err)
	}
	rc1.Close()

	// 2. Test with Seeker (should attempt to launch ParallelReader and roll back)
	r2 := dummyReadCloser{mockSeekReaderAt{bytes.NewReader([]byte{0, 0, 0, 0, 0})}}
	rc2, err := NewReader(p, 0, []io.ReadCloser{r2})
	if err != nil {
		t.Fatalf("Failed to create seekable reader: %v", err)
	}

	// We verify that Close() does not panic after all attempts and rollbacks.
	if err := rc2.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}
