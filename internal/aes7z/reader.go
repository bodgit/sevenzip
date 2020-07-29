package aes7z

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

	"github.com/connesc/cipherio"
)

type readCloser struct {
	rc       io.ReadCloser
	br       io.Reader
	salt, iv []byte
	cycles   int
}

func (rc *readCloser) Close() error {
	return rc.rc.Close()
}

func (rc *readCloser) Password(p string) error {
	block, err := aes.NewCipher(calculateKey(p, rc.cycles, rc.salt))
	if err != nil {
		return err
	}
	rc.br = cipherio.NewBlockReader(rc.rc, cipher.NewCBCDecrypter(block, rc.iv))
	return nil
}

func (rc *readCloser) Read(p []byte) (int, error) {
	if rc.br == nil {
		return 0, errors.New("sevenzip: no password set")
	}
	return rc.br.Read(p)
}

func NewReader(p []byte, _ uint64, rc io.ReadCloser) (io.ReadCloser, error) {
	// Need at least two bytes initially
	if len(p) < 2 {
		return nil, errors.New("sevenzip: not enough properties")
	}

	if p[0]&0xc0 == 0 {
		return nil, errors.New("sevenzip: unsupported compression method")
	}

	nrc := new(readCloser)

	salt := p[0]>>7&1 + p[1]>>4
	iv := p[0]>>6&1 + p[1]&0x0f
	if len(p) != int(2+salt+iv) {
		return nil, errors.New("sevenzip: not enough properties")
	}

	nrc.salt = p[2 : 2+salt]
	nrc.iv = make([]byte, 16)
	copy(nrc.iv, p[2+salt:])

	nrc.cycles = int(p[0] & 0x3f)
	nrc.rc = rc

	return nrc, nil
}
