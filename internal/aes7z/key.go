package aes7z

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

type keyCacheItem struct {
	password string
	cycles   int
	salt     []byte
	key      []byte
}

func (c *keyCacheItem) hittest(password string, cycles int, salt []byte) bool {
	return c.password == password && c.cycles == cycles && bytes.Equal(salt, c.salt)
}

var keyCache []*keyCacheItem = []*keyCacheItem{}
var keyCacheLock sync.RWMutex

func findKeyCached(password string, cycles int, salt []byte) []byte {
	keyCacheLock.RLock()
	defer keyCacheLock.RUnlock()
	for _, kci := range keyCache {
		if kci.hittest(password, cycles, salt) {
			return kci.key
		}
	}

	return nil
}

func recordKeyCached(password string, cycles int, salt []byte, key []byte) {
	keyCacheLock.Lock()
	defer keyCacheLock.Unlock()
	keyCache = append(keyCache, &keyCacheItem{password: password, cycles: cycles, salt: salt, key: key})
}

func calculateKey(password string, cycles int, salt []byte) []byte {
	k := findKeyCached(password, cycles, salt)
	if len(k) > 0 {
		// key found in cache
		return k
	}
	b := bytes.NewBuffer(salt)

	// Convert password to UTF-16LE
	utf16le := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	t := transform.NewWriter(b, utf16le.NewEncoder())
	_, _ = t.Write([]byte(password))

	key := make([]byte, sha256.Size)
	if cycles == 0x3f {
		copy(key, b.Bytes())
	} else {
		h := sha256.New()
		for i := uint64(0); i < 1<<cycles; i++ {
			// These will never error
			_, _ = h.Write(b.Bytes())
			_ = binary.Write(h, binary.LittleEndian, i)
		}
		copy(key, h.Sum(nil))
	}

	recordKeyCached(password, cycles, salt, key)
	return key
}
