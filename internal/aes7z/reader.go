package aes7z

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

	"github.com/connesc/cipherio"
)

type reader struct {
	r, br    io.Reader
	salt, iv []byte
	cycles   int
}

func (r *reader) Password(p string) error {
	block, err := aes.NewCipher(calculateKey(p, r.cycles, r.salt))
	if err != nil {
		return err
	}
	r.br = cipherio.NewBlockReader(r.r, cipher.NewCBCDecrypter(block, r.iv))
	return nil
}

func (r *reader) Read(p []byte) (int, error) {
	if r.br == nil {
		return 0, errors.New("sevenzip: no password set")
	}
	return r.br.Read(p)
}

func NewReader(p []byte, _ uint64, r io.Reader) (io.Reader, error) {
	// Need at least two bytes initially
	if len(p) < 2 {
		return nil, errors.New("sevenzip: not enough properties")
	}

	if p[0]&0xc0 == 0 {
		return nil, errors.New("sevenzip: unsupported compression method")
	}

	nr := new(reader)

	salt := p[0]>>7&1 + p[1]>>4
	iv := p[0]>>6&1 + p[1]&0x0f
	if len(p) != int(2+salt+iv) {
		return nil, errors.New("sevenzip: not enough properties")
	}

	nr.salt = p[2 : 2+salt]
	nr.iv = make([]byte, 16)
	copy(nr.iv, p[2+salt:])

	nr.cycles = int(p[0] & 0x3f)
	nr.r = r

	return nr, nil
}
