package aes7z

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

type cacheKey struct {
	password string
	cycles   int
	salt     string // []byte isn't comparable
}

const (
	cacheSize = 10

	// maxCyclesPower caps the KDF iteration exponent to prevent CPU exhaustion
	// from malicious archives. Standard 7-zip always uses 19 (≈500K rounds,
	// ~10ms). A cap of 24 (≈16M rounds, ~250ms) provides 32× headroom above
	// the standard while keeping the worst-case derivation time bounded.
	// The special value 0x3f bypasses hashing entirely and is not affected.
	maxCyclesPower = 24
)

var errCyclesPowerTooLarge = errors.New("aes7z: cycles power exceeds maximum")

//nolint:gochecknoglobals
var once = sync.OnceValues(func() (*lru.Cache[cacheKey, []byte], error) {
	return lru.New[cacheKey, []byte](cacheSize)
})

func calculateKey(password string, cycles int, salt []byte) ([]byte, error) {
	cache, err := once()
	if err != nil {
		return nil, fmt.Errorf("aes7z: error creating cache: %w", err)
	}

	ck := cacheKey{
		password: password,
		cycles:   cycles,
		salt:     hex.EncodeToString(salt),
	}

	if key, ok := cache.Get(ck); ok {
		return key, nil
	}

	b := bytes.NewBuffer(salt)

	// Convert password to UTF-16LE
	utf16le := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	t := transform.NewWriter(b, utf16le.NewEncoder())
	_, _ = t.Write([]byte(password))

	key := make([]byte, sha256.Size)
	if cycles == 0x3f {
		// Raw mode: key is derived directly from salt+password, no hashing.
		copy(key, b.Bytes())
	} else {
		if cycles > maxCyclesPower {
			return nil, fmt.Errorf("%w: %d > %d", errCyclesPowerTooLarge, cycles, maxCyclesPower)
		}

		h := sha256.New()
		for i := range uint64(1 << cycles) {
			// These will never error
			_, _ = h.Write(b.Bytes())
			_ = binary.Write(h, binary.LittleEndian, i)
		}

		copy(key, h.Sum(nil))
	}

	_ = cache.Add(ck, key)

	return key, nil
}
