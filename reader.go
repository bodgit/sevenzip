package sevenzip

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"math/bits"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bodgit/plumbing"
	"github.com/bodgit/sevenzip/internal/pool"
	"github.com/bodgit/sevenzip/internal/util"
	"github.com/bodgit/windows"
	"github.com/hashicorp/go-multierror"
	"go4.org/readerutil"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

var (
	errFormat         = errors.New("sevenzip: not a valid 7-zip file")
	errAlgorithm      = errors.New("sevenzip: unsupported compression algorithm")
	errChecksum       = errors.New("sevenzip: checksum error")
	errUnexpectedID   = errors.New("sevenzip: unexpected id")
	errTooMuch        = errors.New("sevenzip: too much data")
	errIncompleteRead = errors.New("sevenzip: incomplete read")
)

var newPool pool.Constructor = pool.NewPool

type Reader struct {
	r     io.ReaderAt
	start int64
	end   int64
	si    *streamsInfo
	p     string
	File  []*File
	pool  []pool.Pooler
}

type ReadCloser struct {
	f []*os.File
	Reader
}

type File struct {
	FileHeader
	zip    *Reader
	folder int
	offset int64
}

// Open returns an io.ReadCloser that provides access to the File's contents.
// Multiple files may be read concurrently.
func (f *File) Open() (io.ReadCloser, error) {
	if f.FileHeader.isEmptyStream || f.FileHeader.isEmptyFile {
		// Return empty reader for directory or empty file
		return ioutil.NopCloser(bytes.NewReader(nil)), nil
	}

	r, _, err := f.zip.folderReader(f.zip.si, f.folder)
	if err != nil {
		return nil, err
	}

	if _, err := io.CopyN(ioutil.Discard, r, f.offset); err != nil {
		return nil, err
	}

	return plumbing.LimitReadCloser(r, int64(f.UncompressedSize)), nil
}

// OpenReaderWithPassword will open the 7-zip file specified by name using
// password as the basis of the decryption key and return a ReadCloser. If
// name has a ".001" suffix it is assumed there are multiple volumes and each
// sequential volume will be opened.
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

func readUint64(r io.ByteReader) (uint64, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}

	l := bits.LeadingZeros8(^b)

	var v uint64
	if l < 7 {
		v |= uint64(b&((1<<(8-l))-1)) << (8 * l)
	}

	for i := 0; i < l; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}

		v |= uint64(b) << (8 * i)
	}

	return v, nil
}

func readBool(r io.ByteReader, count uint64) ([]bool, error) {
	defined := make([]bool, count)

	var b, mask byte
	for i := range defined {
		if mask == 0 {
			var err error

			b, err = r.ReadByte()
			if err != nil {
				return nil, err
			}

			mask = 0x80
		}

		defined[i] = (b & mask) != 0
		mask >>= 1
	}

	return defined, nil
}

func readOptionalBool(r io.ByteReader, count uint64) ([]bool, error) {
	all, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if all == 0 {
		return readBool(r, count)
	}

	defined := make([]bool, count)
	for i := range defined {
		defined[i] = true
	}

	return defined, nil
}

func readSizes(r io.ByteReader, count uint64) ([]uint64, error) {
	sizes := make([]uint64, count)

	for i := uint64(0); i < count; i++ {
		size, err := readUint64(r)
		if err != nil {
			return nil, err
		}

		sizes[i] = size
	}

	return sizes, nil
}

func readCRC(r util.Reader, count uint64) ([]uint32, []bool, error) {
	defined, err := readOptionalBool(r, count)
	if err != nil {
		return nil, nil, err
	}

	crcs := make([]uint32, count)

	for i := uint64(0); i < count; i++ {
		var crc uint32
		if err := binary.Read(r, binary.LittleEndian, &crc); err != nil {
			return nil, nil, err
		}

		crcs[i] = crc
	}

	return crcs, defined, nil
}

func readPackInfo(r util.Reader) (*packInfo, error) {
	p := new(packInfo)

	var err error

	p.position, err = readUint64(r)
	if err != nil {
		return nil, err
	}

	p.streams, err = readUint64(r)
	if err != nil {
		return nil, err
	}

	id, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if id == idSize {
		if p.size, err = readSizes(r, p.streams); err != nil {
			return nil, err
		}

		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idCRC {
		if p.digest, p.defined, err = readCRC(r, p.streams); err != nil {
			return nil, err
		}

		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id != idEnd {
		return nil, errUnexpectedID
	}

	return p, nil
}

func readCoder(r util.Reader) (*coder, error) {
	c := new(coder)

	v, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	c.id = make([]byte, v&0xf)
	if n, err := r.Read(c.id); err != nil || n != int(v&0xf) {
		if err != nil {
			return nil, err
		}

		return nil, errIncompleteRead
	}

	if v&0x10 != 0 {
		c.in, err = readUint64(r)
		if err != nil {
			return nil, err
		}

		c.out, err = readUint64(r)
		if err != nil {
			return nil, err
		}
	} else {
		c.in, c.out = 1, 1
	}

	if v&0x20 != 0 {
		size, err := readUint64(r)
		if err != nil {
			return nil, err
		}

		c.properties = make([]byte, size)
		if n, err := r.Read(c.properties); err != nil || n != int(size) {
			if err != nil {
				return nil, err
			}

			return nil, errIncompleteRead
		}
	}

	return c, nil
}

func readFolder(r util.Reader) (*folder, error) {
	f := new(folder)

	coders, err := readUint64(r)
	if err != nil {
		return nil, err
	}

	f.coder = make([]*coder, coders)

	for i := uint64(0); i < coders; i++ {
		if f.coder[i], err = readCoder(r); err != nil {
			return nil, err
		}

		f.in += f.coder[i].in
		f.out += f.coder[i].out
	}

	bindPairs := f.out - 1

	f.bindPair = make([]*bindPair, bindPairs)

	for i := uint64(0); i < bindPairs; i++ {
		in, err := readUint64(r)
		if err != nil {
			return nil, err
		}

		out, err := readUint64(r)
		if err != nil {
			return nil, err
		}

		f.bindPair[i] = &bindPair{
			in:  in,
			out: out,
		}
	}

	f.packedStreams = f.in - bindPairs

	if f.packedStreams == 1 {
		f.packed = []uint64{}
		for i := uint64(0); i < f.in; i++ {
			if f.findInBindPair(i) == nil {
				f.packed = append(f.packed, i)
			}
		}
	} else {
		f.packed = make([]uint64, f.packedStreams)
		for i := uint64(0); i < f.packedStreams; i++ {
			if f.packed[i], err = readUint64(r); err != nil {
				return nil, err
			}
		}
	}

	return f, nil
}

func readUnpackInfo(r util.Reader) (*unpackInfo, error) {
	u := new(unpackInfo)

	if id, err := r.ReadByte(); err != nil || id != idFolder {
		if err != nil {
			return nil, err
		}

		return nil, errUnexpectedID
	}

	folders, err := readUint64(r)
	if err != nil {
		return nil, err
	}

	external, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if external > 0 {
		_, err := readUint64(r)
		if err != nil {
			return nil, err
		}
		// TODO Apparently we seek to this read offset and read the
		// folder information from there. Not clear if the offset is
		// absolute for the whole file, or relative to some known
		// position in the file. Cowardly waiting for an example
		return nil, errors.New("sevenzip: TODO readUnpackInfo external")
	}

	u.folder = make([]*folder, folders)

	for i := uint64(0); i < folders; i++ {
		if u.folder[i], err = readFolder(r); err != nil {
			return nil, err
		}
	}

	if id, err := r.ReadByte(); err != nil || id != idCodersUnpackSize {
		if err != nil {
			return nil, err
		}

		return nil, errUnexpectedID
	}

	for _, f := range u.folder {
		total := uint64(0)
		for _, c := range f.coder {
			total += c.out
		}

		f.size = make([]uint64, total)
		for i := range f.size {
			if f.size[i], err = readUint64(r); err != nil {
				return nil, err
			}
		}
	}

	id, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if id == idCRC {
		if u.digest, u.defined, err = readCRC(r, folders); err != nil {
			return nil, err
		}

		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id != idEnd {
		return nil, errUnexpectedID
	}

	return u, nil
}

func readSubStreamsInfo(r util.Reader, folder []*folder) (*subStreamsInfo, error) {
	s := new(subStreamsInfo)

	id, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	s.streams = make([]uint64, len(folder))
	if id == idNumUnpackStream {
		for i := range s.streams {
			if s.streams[i], err = readUint64(r); err != nil {
				return nil, err
			}
		}

		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	} else {
		for i := range s.streams {
			s.streams[i] = 1
		}
	}

	// Count the files in each stream
	files := uint64(0)
	for _, v := range s.streams {
		files += v
	}

	if id == idSize {
		s.size = make([]uint64, files)
		k := 0

		for i := range s.streams {
			total := uint64(0)

			for j := uint64(1); j < s.streams[i]; j++ {
				if s.size[k], err = readUint64(r); err != nil {
					return nil, err
				}

				total += s.size[k]
				k++
			}

			s.size[k] = folder[i].unpackSize() - total
			k++
		}

		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idCRC {
		if s.digest, s.defined, err = readCRC(r, files); err != nil {
			return nil, err
		}

		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id != idEnd {
		return nil, errUnexpectedID
	}

	return s, nil
}

func readStreamsInfo(r util.Reader) (*streamsInfo, error) {
	s := new(streamsInfo)

	id, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if id == idPackInfo {
		if s.packInfo, err = readPackInfo(r); err != nil {
			return nil, err
		}

		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idUnpackInfo {
		if s.unpackInfo, err = readUnpackInfo(r); err != nil {
			return nil, err
		}

		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idSubStreamsInfo {
		if s.subStreamsInfo, err = readSubStreamsInfo(r, s.unpackInfo.folder); err != nil {
			return nil, err
		}

		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id != idEnd {
		return nil, errUnexpectedID
	}

	return s, nil
}

func readTimes(r util.Reader, count uint64) ([]time.Time, error) {
	_, err := readOptionalBool(r, count)
	if err != nil {
		return nil, err
	}

	external, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if external > 0 {
		_, err := readUint64(r)
		if err != nil {
			return nil, err
		}
		// TODO Apparently we seek to this read offset and read the
		// folder information from there. Not clear if the offset is
		// absolute for the whole file, or relative to some known
		// position in the file. Cowardly waiting for an example
		return nil, errors.New("sevenzip: TODO readTimes external")
	}

	times := make([]time.Time, 0, count)

	for i := uint64(0); i < count; i++ {
		var ft windows.Filetime
		if err := binary.Read(r, binary.LittleEndian, &ft); err != nil {
			return nil, err
		}

		times = append(times, time.Unix(0, ft.Nanoseconds()).UTC())
	}

	return times, nil
}

func splitNull(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	if i := bytes.IndexRune(data, rune(0)); i >= 0 {
		return i + 1, data[0:i], nil
	}

	if atEOF {
		return len(data), data, nil
	}

	return
}

func readNames(r util.Reader, count, length uint64) ([]string, error) {
	external, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if external > 0 {
		_, err := readUint64(r)
		if err != nil {
			return nil, err
		}
		// TODO Apparently we seek to this read offset and read the
		// folder information from there. Not clear if the offset is
		// absolute for the whole file, or relative to some known
		// position in the file. Cowardly waiting for an example
		return nil, errors.New("sevenzip: TODO readNames external")
	}

	utf16le := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	scanner := bufio.NewScanner(transform.NewReader(io.LimitReader(r, int64(length-1)), utf16le.NewDecoder()))
	scanner.Split(splitNull)

	names, i := make([]string, 0, count), uint64(0)
	for scanner.Scan() {
		names = append(names, scanner.Text())
		i++
	}

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	if i != count {
		return nil, errors.New("sevenzip: wrong number of filenames")
	}

	return names, nil
}

func readAttributes(r util.Reader, count uint64) ([]uint32, error) {
	_, err := readOptionalBool(r, count)
	if err != nil {
		return nil, err
	}

	external, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if external > 0 {
		_, err := readUint64(r)
		if err != nil {
			return nil, err
		}
		// TODO Apparently we seek to this read offset and read the
		// folder information from there. Not clear if the offset is
		// absolute for the whole file, or relative to some known
		// position in the file. Cowardly waiting for an example
		return nil, errors.New("sevenzip: TODO readAttributes external")
	}

	attributes := make([]uint32, count)
	for i := uint64(0); i < count; i++ {
		if err := binary.Read(r, binary.LittleEndian, &attributes[i]); err != nil {
			return nil, err
		}
	}

	return attributes, nil
}

func readFilesInfo(r util.Reader) (*filesInfo, error) {
	f := new(filesInfo)

	files, err := readUint64(r)
	if err != nil {
		return nil, err
	}

	f.file = make([]FileHeader, files)

	var emptyStreams uint64

	for {
		property, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		if property == idEnd {
			break
		}

		length, err := readUint64(r)
		if err != nil {
			return nil, err
		}

		switch property {
		case idEmptyStream:
			empty, err := readBool(r, files)
			if err != nil {
				return nil, err
			}

			for i := range f.file {
				f.file[i].isEmptyStream = empty[i]

				if empty[i] {
					emptyStreams++
				}
			}
		case idEmptyFile:
			empty, err := readBool(r, emptyStreams)
			if err != nil {
				return nil, err
			}

			j := 0

			for i := range f.file {
				if f.file[i].isEmptyStream {
					f.file[i].isEmptyFile = empty[j]
				}
				j++
			}
		case idCTime:
			times, err := readTimes(r, files)
			if err != nil {
				return nil, err
			}

			for i, t := range times {
				f.file[i].Created = t
			}
		case idATime:
			times, err := readTimes(r, files)
			if err != nil {
				return nil, err
			}

			for i, t := range times {
				f.file[i].Accessed = t
			}
		case idMTime:
			times, err := readTimes(r, files)
			if err != nil {
				return nil, err
			}

			for i, t := range times {
				f.file[i].Modified = t
			}
		case idName:
			names, err := readNames(r, files, length)
			if err != nil {
				return nil, err
			}

			for i, n := range names {
				f.file[i].Name = n
			}
		case idWinAttributes:
			attributes, err := readAttributes(r, files)
			if err != nil {
				return nil, err
			}

			for i, a := range attributes {
				f.file[i].Attributes = a
			}
		case idStartPos:
			return nil, errors.New("sevenzip: TODO idStartPos")
		case idDummy:
			if _, err := io.CopyN(ioutil.Discard, r, int64(length)); err != nil {
				return nil, err
			}
		default:
			return nil, errUnexpectedID
		}
	}

	return f, nil
}

func readHeader(r util.Reader) (*header, error) {
	h := new(header)

	id, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if id == idArchiveProperties {
		return nil, errors.New("sevenzip: TODO idArchiveProperties")

		//nolint:govet
		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idAdditionalStreamsInfo {
		return nil, errors.New("sevenzip: TODO idAdditionalStreamsInfo")

		//nolint:govet
		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idMainStreamsInfo {
		if h.streamsInfo, err = readStreamsInfo(r); err != nil {
			return nil, err
		}

		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idFilesInfo {
		if h.filesInfo, err = readFilesInfo(r); err != nil {
			return nil, err
		}

		id, err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id != idEnd {
		return nil, errUnexpectedID
	}

	j := 0

	for i := range h.filesInfo.file {
		if h.filesInfo.file[i].isEmptyStream {
			continue
		}

		h.filesInfo.file[i].CRC32 = h.streamsInfo.subStreamsInfo.digest[j]
		_, h.filesInfo.file[i].UncompressedSize = h.streamsInfo.FileFolderAndSize(j)
		j++
	}

	return h, nil
}

func (z *Reader) folderReader(si *streamsInfo, f int) (*folderReadCloser, uint32, error) {
	// Create a SectionReader covering all of the streams data
	return si.FolderReader(io.NewSectionReader(z.r, z.start, z.end), f, z.p)
}

func (z *Reader) init(r io.ReaderAt, size int64) error {
	h := crc32.NewIEEE()
	tra := plumbing.TeeReaderAt(r, h)
	sr := io.NewSectionReader(tra, 0, size) // Will only read first 32 bytes

	var sh signatureHeader
	if err := binary.Read(sr, binary.LittleEndian, &sh); err != nil {
		return err
	}

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
	if n, _ := io.CopyN(ioutil.Discard, br, 1); n != 0 {
		return errTooMuch
	}

	// CRC should match the one from the start header
	if !util.CRC32Equal(h.Sum(nil), start.CRC) {
		return errChecksum
	}

	// If the header was encoded we should have sufficient information now
	// to decode it
	if id == idEncodedHeader && streamsInfo != nil {
		if streamsInfo.Folders() != 1 {
			return errors.New("sevenzip: expected only one folder in header stream")
		}

		fr, crc, err := z.folderReader(streamsInfo, 0)
		if err != nil {
			return err
		}
		defer fr.Close()

		br = bufio.NewReader(fr)

		if id, err = br.ReadByte(); err != nil || id != idHeader {
			if err != nil {
				return err
			}

			return errUnexpectedID
		}

		if header, err = readHeader(br); err != nil {
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
