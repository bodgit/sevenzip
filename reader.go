package sevenzip

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bodgit/plumbing"
	"github.com/bodgit/sevenzip/internal/pool"
	"github.com/bodgit/sevenzip/internal/util"
	"github.com/hashicorp/go-multierror"
	"go4.org/readerutil"
)

var (
	errFormat   = errors.New("sevenzip: not a valid 7-zip file")
	errChecksum = errors.New("sevenzip: checksum error")
	errTooMuch  = errors.New("sevenzip: too much data")
)

//nolint:gochecknoglobals
var newPool pool.Constructor = pool.NewPool

// A Reader serves content from a 7-Zip archive.
type Reader struct {
	r     io.ReaderAt
	start int64
	end   int64
	si    *streamsInfo
	p     string
	File  []*File
	pool  []pool.Pooler
}

// A ReadCloser is a Reader that must be closed when no longer needed.
type ReadCloser struct {
	f []*os.File
	Reader
}

// A File is a single file in a 7-Zip archive. The file information is in the
// embedded FileHeader. The file content can be accessed by calling Open.
type File struct {
	FileHeader
	zip    *Reader
	folder int
	offset int64
}

type fileReader struct {
	rc util.SizeReadSeekCloser
	f  *File
}

func (fr *fileReader) Read(p []byte) (int, error) {
	return fr.rc.Read(p)
}

func (fr *fileReader) Close() error {
	if fr.rc == nil {
		return nil
	}

	offset, err := fr.rc.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	if offset == fr.rc.Size() { // EOF reached
		if err := fr.rc.Close(); err != nil {
			return err
		}
	} else {
		f := fr.f
		if _, err := f.zip.pool[f.folder].Put(offset, fr.rc); err != nil {
			return err
		}
	}

	fr.rc = nil

	return nil
}

// Open returns an io.ReadCloser that provides access to the File's contents.
// Multiple files may be read concurrently.
func (f *File) Open() (io.ReadCloser, error) {
	if f.FileHeader.isEmptyStream || f.FileHeader.isEmptyFile {
		// Return empty reader for directory or empty file
		return io.NopCloser(bytes.NewReader(nil)), nil
	}

	var err error

	rc, _ := f.zip.pool[f.folder].Get(f.offset)
	if rc == nil {
		rc, _, err = f.zip.folderReader(f.zip.si, f.folder)
		if err != nil {
			return nil, err
		}
	}

	if _, err = rc.Seek(f.offset, io.SeekStart); err != nil {
		return nil, err
	}

	fr := &fileReader{
		rc: rc,
		f:  f,
	}

	return plumbing.LimitReadCloser(fr, int64(f.UncompressedSize)), nil
}

// OpenReaderWithPassword will open the 7-zip file specified by name using
// password as the basis of the decryption key and return a ReadCloser. If
// name has a ".001" suffix it is assumed there are multiple volumes and each
// sequential volume will be opened.
//nolint:cyclop,funlen
func OpenReaderWithPassword(name, password string) (*ReadCloser, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		err = multierror.Append(err, f.Close())

		return nil, err
	}

	var reader io.ReaderAt = f

	size := info.Size()
	files := []*os.File{f}

	if ext := filepath.Ext(name); ext == ".001" {
		sr := []readerutil.SizeReaderAt{io.NewSectionReader(f, 0, size)}

		for i := 2; true; i++ {
			f, err := os.Open(fmt.Sprintf("%s.%03d", strings.TrimSuffix(name, ext), i))
			if err != nil {
				if os.IsNotExist(err) {
					break
				}

				for _, file := range files {
					err = multierror.Append(err, file.Close())
				}

				return nil, err
			}

			files = append(files, f)

			info, err = f.Stat()
			if err != nil {
				for _, file := range files {
					err = multierror.Append(err, file.Close())
				}

				return nil, err
			}

			sr = append(sr, io.NewSectionReader(f, 0, info.Size()))
		}

		mr := readerutil.NewMultiReaderAt(sr...)
		reader, size = mr, mr.Size()
	}

	r := new(ReadCloser)
	r.p = password

	if err := r.init(reader, size); err != nil {
		for _, file := range files {
			err = multierror.Append(err, file.Close())
		}

		return nil, err
	}

	r.f = files

	return r, nil
}

// OpenReader will open the 7-zip file specified by name and return a
// ReadCloser. If name has a ".001" suffix it is assumed there are multiple
// volumes and each sequential volume will be opened.
func OpenReader(name string) (*ReadCloser, error) {
	return OpenReaderWithPassword(name, "")
}

// NewReaderWithPassword returns a new Reader reading from r using password as
// the basis of the decryption key, which is assumed to have the given size in
// bytes.
func NewReaderWithPassword(r io.ReaderAt, size int64, password string) (*Reader, error) {
	if size < 0 {
		return nil, errors.New("sevenzip: size cannot be negative")
	}

	zr := new(Reader)
	zr.p = password

	if err := zr.init(r, size); err != nil {
		return nil, err
	}

	return zr, nil
}

// NewReader returns a new Reader reading from r, which is assumed to have the
// given size in bytes.
func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	return NewReaderWithPassword(r, size, "")
}

func (z *Reader) folderReader(si *streamsInfo, f int) (*folderReadCloser, uint32, error) {
	// Create a SectionReader covering all of the streams data
	return si.FolderReader(io.NewSectionReader(z.r, z.start, z.end), f, z.p)
}

//nolint:cyclop,funlen,gocognit
func (z *Reader) init(r io.ReaderAt, size int64) error {
	h := crc32.NewIEEE()
	tra := plumbing.TeeReaderAt(r, h)
	sr := io.NewSectionReader(tra, 0, size) // Will only read first 32 bytes

	var sh signatureHeader
	if err := binary.Read(sr, binary.LittleEndian, &sh); err != nil {
		return err
	}

	signature := []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}
	if !bytes.Equal(sh.Signature[:], signature) {
		return errFormat
	}

	z.r = r

	h.Reset()

	var (
		err   error
		start startHeader
	)

	if err = binary.Read(sr, binary.LittleEndian, &start); err != nil {
		return err
	}

	// CRC of the start header should match
	if !util.CRC32Equal(h.Sum(nil), sh.CRC) {
		return errChecksum
	}

	// Work out where we are in the file (32, avoiding magic numbers)
	if z.start, err = sr.Seek(0, io.SeekCurrent); err != nil {
		return err
	}

	// Seek over the streams
	if z.end, err = sr.Seek(int64(start.Offset), io.SeekCurrent); err != nil {
		return err
	}

	h.Reset()

	// Bound bufio.Reader otherwise it can read trailing garbage which screws up the CRC check
	br := bufio.NewReader(io.NewSectionReader(tra, z.end, int64(start.Size)))

	id, err := br.ReadByte()
	if err != nil {
		return err
	}

	var (
		header      *header
		streamsInfo *streamsInfo
	)

	switch id {
	case idHeader:
		if header, err = readHeader(br); err != nil {
			return err
		}
	case idEncodedHeader:
		if streamsInfo, err = readStreamsInfo(br); err != nil {
			return err
		}
	default:
		return errUnexpectedID
	}

	// If there's more data to read, we've not parsed this correctly. This
	// won't break with trailing data as the bufio.Reader was bounded
	if n, _ := io.CopyN(io.Discard, br, 1); n != 0 {
		return errTooMuch
	}

	// CRC should match the one from the start header
	if !util.CRC32Equal(h.Sum(nil), start.CRC) {
		return errChecksum
	}

	// If the header was encoded we should have sufficient information now
	// to decode it
	if streamsInfo != nil {
		if streamsInfo.Folders() != 1 {
			return errors.New("sevenzip: expected only one folder in header stream")
		}

		fr, crc, err := z.folderReader(streamsInfo, 0)
		if err != nil {
			return err
		}
		defer fr.Close()

		if header, err = readEncodedHeader(util.ByteReadCloser(fr)); err != nil {
			return err
		}

		if crc != 0 && !util.CRC32Equal(fr.Checksum(), crc) {
			return errChecksum
		}
	}

	z.si = header.streamsInfo

	z.pool = make([]pool.Pooler, z.si.Folders())
	for i := range z.pool {
		if z.pool[i], err = newPool(); err != nil {
			return err
		}
	}

	// spew.Dump(header)

	folder, offset := 0, int64(0)
	z.File = make([]*File, 0, len(header.filesInfo.file))
	j := 0

	for _, fh := range header.filesInfo.file {
		f := new(File)
		f.zip = z
		f.FileHeader = fh

		if f.FileHeader.FileInfo().IsDir() && !strings.HasSuffix(f.FileHeader.Name, "/") {
			f.FileHeader.Name += "/"
		}

		if !fh.isEmptyStream && !fh.isEmptyFile {
			f.folder, _ = header.streamsInfo.FileFolderAndSize(j)

			if f.folder != folder {
				offset = 0
			}

			f.offset = offset
			offset += int64(f.UncompressedSize)
			folder = f.folder
			j++
		}

		z.File = append(z.File, f)
	}

	return nil
}

// Close closes the 7-zip file or volumes, rendering them unusable for I/O.
func (rc *ReadCloser) Close() error {
	var err *multierror.Error
	for _, f := range rc.f {
		err = multierror.Append(err, f.Close())
	}

	return err.ErrorOrNil()
}
