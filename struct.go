package sevenzip

import (
	"hash"
	"hash/crc32"
	"io"
	"time"

	"github.com/bodgit/plumbing"
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

type cryptoReadCloser interface {
	io.ReadCloser
	Password(string) error
}

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
	packedStreams uint64
	coder         []*coder
	bindPair      []*bindPair
	size          []uint64
	packed        []uint64
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

func (f *folder) coderReader(rc io.ReadCloser, coder uint64, password string) (io.ReadCloser, error) {
	dcomp := decompressor(f.coder[coder].id)
	if dcomp == nil {
		return nil, errAlgorithm
	}
	cr, err := dcomp(f.coder[coder].properties, f.size[coder], rc)
	if err != nil {
		return nil, err
	}

	if crc, ok := cr.(cryptoReadCloser); ok {
		if err = crc.Password(password); err != nil {
			return nil, err
		}
	}

	return plumbing.LimitReadCloser(cr, int64(f.size[coder])), nil
}

func (f *folder) reader(rc io.ReadCloser, password string) (io.ReadCloser, error) {
	fr, err := f.coderReader(rc, 0, password)
	if err != nil {
		return nil, err
	}

	for _, bp := range f.bindPair {
		if fr, err = f.coderReader(fr, bp.in, password); err != nil {
			return nil, err
		}
	}

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

func (si *streamsInfo) FolderOffset(folder int) int64 {
	offset := uint64(0)
	for i, k := 0, uint64(0); i < folder; i++ {
		for j := k; j < k+si.unpackInfo.folder[i].packedStreams; j++ {
			offset += si.packInfo.size[j]
		}
		k += si.unpackInfo.folder[i].packedStreams
	}
	return int64(si.packInfo.position + offset)
}

type crcReadCloser struct {
	rc io.ReadCloser
	h  hash.Hash
}

func (rc *crcReadCloser) Read(p []byte) (int, error) {
	return rc.rc.Read(p)
}

func (rc *crcReadCloser) Close() error {
	return rc.rc.Close()
}

func (rc *crcReadCloser) Checksum() []byte {
	return rc.h.Sum(nil)
}

func newCRCReadCloser(rc io.ReadCloser) io.ReadCloser {
	nrc := new(crcReadCloser)
	nrc.h = crc32.NewIEEE()
	nrc.rc = plumbing.TeeReadCloser(rc, nrc.h)
	return nrc
}

func (si *streamsInfo) FolderReader(rc io.ReadCloser, folder int, password string) (io.ReadCloser, uint32, error) {
	fr, err := si.unpackInfo.folder[folder].reader(rc, password)
	if err != nil {
		return nil, 0, err
	}
	if si.unpackInfo.digest != nil {
		return newCRCReadCloser(fr), si.unpackInfo.digest[folder], nil
	}
	return fr, 0, nil
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
