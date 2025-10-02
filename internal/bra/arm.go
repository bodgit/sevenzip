package bra

import (
	"encoding/binary"
	"io"
)

const armAlignment = 4

type arm struct {
	ip uint32
}

func (c *arm) Size() int { return armAlignment }

func (c *arm) Convert(b []byte, encoding bool) int {
	if len(b) < c.Size() {
		return 0
	}

	if c.ip == 0 {
		c.ip = armAlignment
	}

	var i int

	for i = 0; i < len(b) & ^(armAlignment-1); i += armAlignment {
		v := binary.LittleEndian.Uint32(b[i:])

		c.ip += armAlignment

		if b[i+3] == 0xeb {
			if encoding {
				v += c.ip >> 2
			} else {
				v -= c.ip >> 2
			}

			v &= 0x00ffffff
			v |= 0xeb000000
		}

		binary.LittleEndian.PutUint32(b[i:], v)
	}

	return i
}

// NewARMReader returns a new ARM io.ReadCloser.
func NewARMReader(_ []byte, _ uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	return newReader(readers, new(arm))
}
