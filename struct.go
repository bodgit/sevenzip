package sevenzip

import (
	"hash"
	"hash/crc32"
	"io"
	"time"
)

const (
	idEnd = iota
	idHeader
	idArchiveProperties
	idAdditionalStreamsInfo
	idMainStreamsInfo
	idFilesInfo
	idPackInfo
	idUnpackInfo
	idSubStreamsInfo
	idSize
	idCRC
	idFolder
	idCodersUnpackSize
	idNumUnpackStream
	idEmptyStream
	idEmptyFile
	idAnti
	idName
	idCTime
	idATime
	idMTime
	idWinAttributes
	idComment
	idEncodedHeader
	idStartPos
	idDummy
)

var (
	signature = []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}
)

type signatureHeader struct {
	Signature [6]byte
	Major     byte
	Minor     byte
	CRC       uint32
}

type startHeader struct {
	Offset uint64
	Size   uint64
	CRC    uint32
}

type packInfo struct {
	position uint64
	streams  uint64
	size     []uint64
	digest   []uint32
	defined  []bool
}

type coder struct {
	id         []byte
	in, out    uint64
	properties []byte
}

type bindPair struct {
	in, out uint64
}

type folder struct {
	coder    []*coder
	bindPair []*bindPair
	size     []uint64
	packed   []uint64
}

func (f *folder) findInBindPair(i uint64) *bindPair {
	for _, v := range f.bindPair {
		if v.in == i {
			return v
		}
	}
	return nil
}

func (f *folder) findOutBindPair(i uint64) *bindPair {
	for _, v := range f.bindPair {
		if v.out == i {
			return v
		}
	}
	return nil
}

type folderReader struct {
	h hash.Hash
	r io.Reader
}

func (fr *folderReader) Read(p []byte) (int, error) {
	return fr.r.Read(p)
}

func (fr *folderReader) CRC32() []byte {
	return fr.h.Sum(nil)
}

func (f *folder) reader(r io.Reader, password string) (*folderReader, error) {
	dcomp := decompressor(f.coder[0].id)
	if dcomp == nil {
		return nil, errAlgorithm
	}
	rc, err := dcomp(f.coder[0].properties, f.size[0], r)
	if err != nil {
		return nil, err
	}

	if cr, ok := rc.(cryptoReader); ok {
		if err = cr.Password(password); err != nil {
			return nil, err
		}
	}

	rc = io.LimitReader(rc, int64(f.size[0]))

	for _, bp := range f.bindPair {
		dcomp := decompressor(f.coder[bp.in].id)
		if dcomp == nil {
			return nil, errAlgorithm
		}
		rc, err = dcomp(f.coder[bp.in].properties, f.size[bp.in], rc)
		if err != nil {
			return nil, err
		}

		if cr, ok := rc.(cryptoReader); ok {
			if err = cr.Password(password); err != nil {
				return nil, err
			}
		}

		rc = io.LimitReader(rc, int64(f.size[bp.in]))
	}

	fr := new(folderReader)

	fr.h = crc32.NewIEEE()
	fr.r = io.TeeReader(rc, fr.h)

	return fr, nil
}

func (f *folder) unpackSize() uint64 {
	if len(f.size) == 0 {
		return 0
	}
	for i := len(f.size) - 1; i >= 0; i-- {
		if f.findOutBindPair(uint64(i)) == nil {
			return f.size[i]
		}
	}
	return f.size[len(f.size)-1]
}

type unpackInfo struct {
	folder  []*folder
	digest  []uint32
	defined []bool
}

func (ui *unpackInfo) folderReader(f int, r io.Reader, password string) (*folderReader, uint32, error) {
	fr, err := ui.folder[f].reader(r, password)
	if err != nil {
		return nil, 0, err
	}
	return fr, ui.digest[f], nil
}

type subStreamsInfo struct {
	streams []uint64
	size    []uint64
	digest  []uint32
	defined []bool
}

type streamsInfo struct {
	packInfo       *packInfo
	unpackInfo     *unpackInfo
	subStreamsInfo *subStreamsInfo
}

type file struct {
	name                string
	ctime, atime, mtime time.Time
}

type filesInfo struct {
	file []file
}

type header struct {
	streamsInfo *streamsInfo
	filesInfo   *filesInfo
}
