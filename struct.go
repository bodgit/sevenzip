package sevenzip

import (
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"path"
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

func (c *coder) isSimple() bool {
	return c.in == 1 && c.out == 1
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
	// XXX We can't currently handle complex coders (>1 in/out stream).
	// Yes BCJ2, that means you
	for _, c := range f.coder {
		if !c.isSimple() {
			return nil, errors.New("sevenzip: TODO complex coders")
		}
	}

	fr, err := f.coderReader(rc, 0, password)
	if err != nil {
		return nil, err
	}

	// XXX I don't think I'm interpreting the bind pairs correctly here
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
	attributes          uint32
}

type filesInfo struct {
	file []file
}

type header struct {
	streamsInfo *streamsInfo
	filesInfo   *filesInfo
}

type FileHeader struct {
	Name             string
	Created          time.Time
	Accessed         time.Time
	Modified         time.Time
	Attributes       uint32
	CRC32            uint32
	UncompressedSize uint64
}

func (h *FileHeader) FileInfo() os.FileInfo {
	return headerFileInfo{h}
}

type headerFileInfo struct {
	fh *FileHeader
}

func (fi headerFileInfo) Name() string {
	return path.Base(fi.fh.Name)
}

func (fi headerFileInfo) Size() int64 {
	return int64(fi.fh.UncompressedSize)
}

func (fi headerFileInfo) IsDir() bool {
	return fi.Mode().IsDir()
}

func (fi headerFileInfo) ModTime() time.Time {
	return fi.fh.Modified.UTC()
}
func (fi headerFileInfo) Mode() os.FileMode {
	return fi.fh.Mode()
}

func (fi headerFileInfo) Sys() interface{} {
	return fi.fh
}

const (
	// Unix constants. The specification doesn't mention them,
	// but these seem to be the values agreed on by tools.
	s_IFMT   = 0xf000
	s_IFSOCK = 0xc000
	s_IFLNK  = 0xa000
	s_IFREG  = 0x8000
	s_IFBLK  = 0x6000
	s_IFDIR  = 0x4000
	s_IFCHR  = 0x2000
	s_IFIFO  = 0x1000
	s_ISUID  = 0x800
	s_ISGID  = 0x400
	s_ISVTX  = 0x200

	msdosDir      = 0x10
	msdosReadOnly = 0x01
)

func (h *FileHeader) Mode() (mode os.FileMode) {
	// Prefer the POSIX attributes if they're present
	if h.Attributes&0xf0000000 != 0 {
		mode = unixModeToFileMode(h.Attributes >> 16)
	} else {
		mode = msdosModeToFileMode(h.Attributes)
	}
	return
}

func msdosModeToFileMode(m uint32) (mode os.FileMode) {
	if m&msdosDir != 0 {
		mode = os.ModeDir | 0777
	} else {
		mode = 0666
	}
	if m&msdosReadOnly != 0 {
		mode &^= 0222
	}
	return mode
}

func unixModeToFileMode(m uint32) os.FileMode {
	mode := os.FileMode(m & 0777)
	switch m & s_IFMT {
	case s_IFBLK:
		mode |= os.ModeDevice
	case s_IFCHR:
		mode |= os.ModeDevice | os.ModeCharDevice
	case s_IFDIR:
		mode |= os.ModeDir
	case s_IFIFO:
		mode |= os.ModeNamedPipe
	case s_IFLNK:
		mode |= os.ModeSymlink
	case s_IFREG:
		// nothing to do
	case s_IFSOCK:
		mode |= os.ModeSocket
	}
	if m&s_ISGID != 0 {
		mode |= os.ModeSetgid
	}
	if m&s_ISUID != 0 {
		mode |= os.ModeSetuid
	}
	if m&s_ISVTX != 0 {
		mode |= os.ModeSticky
	}
	return mode
}
