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
	seekStartFail   bool
	seekCurrentFail bool
	seekEndFail     bool
	currentOffset   int64
}

func (m mockSeekReaderAt) ReadAt(_ []byte, _ int64) (int, error) {
	return 0, io.EOF
}

func (m mockSeekReaderAt) Seek(_ int64, whence int) (int64, error) {
	if whence == io.SeekStart && m.seekStartFail {
		return 0, errors.New("seek start failed")
	}

	if whence == io.SeekCurrent {
		if m.seekCurrentFail {
			return 0, errors.New("seek current failed")
		}

		return m.currentOffset, nil
	}

	if whence == io.SeekEnd {
		if m.seekEndFail {
			return 0, errors.New("seek end failed")
		}

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

	_ = rc1.Close()

	// 2. Test with Seeker (should attempt to launch ParallelReader and roll back)
	r2 := dummyReadCloser{mockSeekReaderAt{Reader: bytes.NewReader([]byte{0, 0, 0, 0, 0})}}

	rc2, err := NewReader(p, 0, []io.ReadCloser{r2})
	if err != nil {
		t.Fatalf("Failed to create seekable reader: %v", err)
	}

	// We verify that Close() does not panic after all attempts and rollbacks.
	if err := rc2.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestStreamSizeBySeeking_Errors(t *testing.T) {
	s := mockSeekReaderAt{Reader: bytes.NewReader(nil), seekCurrentFail: true}

	_, err := streamSizeBySeeking(s)
	if err == nil {
		t.Error("expected error for seek current failure")
	}

	s = mockSeekReaderAt{Reader: bytes.NewReader(nil), seekEndFail: true}

	_, err = streamSizeBySeeking(s)
	if err == nil {
		t.Error("expected error for seek end failure")
	}

	s = mockSeekReaderAt{Reader: bytes.NewReader(nil), seekStartFail: true}

	_, err = streamSizeBySeeking(s)
	if err == nil {
		t.Error("expected error for seek start failure")
	}
}

func TestTryParallelReader_Offsets(t *testing.T) {
	p := []byte{0}
	r2 := dummyReadCloser{mockSeekReaderAt{Reader: bytes.NewReader([]byte{0, 0, 0, 0, 0}), currentOffset: 10}}

	rc2, err := NewReader(p, 0, []io.ReadCloser{r2})
	if err != nil {
		t.Fatalf("Failed to create seekable reader: %v", err)
	}

	_ = rc2.Close()
}

func TestTryParallelReader_Errors(t *testing.T) {
	p := []byte{0}

	// Test failure at SeekCurrent (should fallback to NewReader2 and succeed)
	r1 := dummyReadCloser{mockSeekReaderAt{Reader: bytes.NewReader([]byte{0, 0, 0, 0, 0}), seekCurrentFail: true}}

	rc1, err := NewReader(p, 0, []io.ReadCloser{r1})
	if err != nil {
		t.Fatalf("Failed to create reader despite SeekCurrent error: %v", err)
	}

	_ = rc1.Close()

	// Test failure at streamSizeBySeeking (should fallback to NewReader2 and succeed)
	r2 := dummyReadCloser{mockSeekReaderAt{Reader: bytes.NewReader([]byte{0, 0, 0, 0, 0}), seekEndFail: true}}

	rc2, err := NewReader(p, 0, []io.ReadCloser{r2})
	if err != nil {
		t.Fatalf("Failed to create reader despite SeekEnd error: %v", err)
	}

	_ = rc2.Close()
}
