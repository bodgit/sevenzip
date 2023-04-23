package aes7z

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

var errProperties = errors.New("aes7z: not enough properties")

type readCloser struct {
	rc       io.ReadCloser
	salt, iv []byte
	cycles   int
	cbc      cipher.BlockMode
	buf      bytes.Buffer
}

func (rc *readCloser) Close() error {
	var err error
	if rc.rc != nil {
		err = rc.rc.Close()
		rc.rc = nil
	}

	return err
}

func (rc *readCloser) Password(p string) error {
	block, err := aes.NewCipher(calculateKey(p, rc.cycles, rc.salt))
	if err != nil {
		return err
	}

	rc.cbc = cipher.NewCBCDecrypter(block, rc.iv)

	return nil
}

func (rc *readCloser) Read(p []byte) (int, error) {
	if rc.rc == nil {
		return 0, errors.New("aes7z: Read after Close")
	}

	if rc.cbc == nil {
		return 0, errors.New("aes7z: no password set")
	}

	var block [aes.BlockSize]byte

	for rc.buf.Len() < len(p) {
		if _, err := io.ReadFull(rc.rc, block[:]); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return 0, err
		}

		rc.cbc.CryptBlocks(block[:], block[:])

		_, _ = rc.buf.Write(block[:])
	}

	return rc.buf.Read(p)
}

// NewReader returns a new AES-256-CBC & SHA-256 io.ReadCloser. The Password
// method must be called before attempting to call Read so that the block
// cipher is correctly initialised.
func NewReader(p []byte, _ uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	if len(readers) != 1 {
		return nil, errors.New("aes7z: need exactly one reader")
	}

	// Need at least two bytes initially
	if len(p) < 2 {
		return nil, errProperties
	}

	if p[0]&0xc0 == 0 {
		return nil, errors.New("aes7z: unsupported compression method")
	}

	rc := new(readCloser)

	salt := p[0]>>7&1 + p[1]>>4
	iv := p[0]>>6&1 + p[1]&0x0f

	if len(p) != int(2+salt+iv) {
		return nil, errProperties
	}

	rc.salt = p[2 : 2+salt]
	rc.iv = make([]byte, aes.BlockSize)
	copy(rc.iv, p[2+salt:])

	rc.cycles = int(p[0] & 0x3f)
	rc.rc = readers[0]

	return rc, nil
}
