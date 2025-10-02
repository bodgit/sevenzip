package bra

import (
	"encoding/binary"
	"io"
)

const arm64Alignment = 4

type arm64 struct {
	ip uint32
}

func (c *arm64) Size() int { return arm64Alignment }

func (c *arm64) Convert(b []byte, encoding bool) int {
	if len(b) < c.Size() {
		return 0
	}

	var i int

	for i = 0; i < len(b) & ^(arm64Alignment-1); i, c.ip = i+arm64Alignment, c.ip+arm64Alignment {
		v := binary.LittleEndian.Uint32(b[i:])

		if (v-0x94000000)&0xfc000000 == 0 {
			if encoding {
				v += c.ip >> 2
			} else {
				v -= c.ip >> 2
			}

			v &= 0x03ffffff
			v |= 0x94000000

			binary.LittleEndian.PutUint32(b[i:], v)

			continue
		}

		v -= 0x90000000

		if v&0x9f000000 == 0 {
			const (
				flag = uint32(1) << (24 - 4)
				mask = uint32(1)<<24 - flag<<1
			)

			v += flag

			if v&mask > 0 {
				continue
			}

			z, ip := v&0xffffffe0|v>>26, (c.ip>>(12-3)) & ^uint32(7)

			if encoding {
				z += ip
			} else {
				z -= ip
			}

			v &= 0x1f
			v |= 0x90000000
			v |= z << 26
			v |= 0x00ffffe0 & ((z & (flag<<1 - 1)) - flag)

			binary.LittleEndian.PutUint32(b[i:], v)
		}
	}

	return i
}

// NewARM64Reader returns a new ARM64 io.ReadCloser.
func NewARM64Reader(_ []byte, _ uint64, readers []io.ReadCloser) (io.ReadCloser, error) {
	return newReader(readers, new(arm64))
}
