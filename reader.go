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
	"time"

	"github.com/bodgit/plumbing"
	"github.com/bodgit/windows"
	"github.com/davecgh/go-spew/spew"
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

type Reader struct {
	r     io.ReaderAt
	start int64
	end   int64
	p     string
	File  []*File
}

type ReadCloser struct {
	f *os.File
	Reader
}

type headerReader interface {
	io.Reader
	io.ByteReader
}

type checksumReadCloser interface {
	io.ReadCloser
	Checksum() []byte
}

type FileHeader struct {
	Name             string
	Created          time.Time
	Accessed         time.Time
	Modified         time.Time
	CRC32            uint32
	UncompressedSize uint64
}

type File struct {
	FileHeader
}

func (f *File) Open() (io.ReadCloser, error) {
	return nil, nil
}

func OpenReaderWithPassword(name, password string) (*ReadCloser, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	r := new(ReadCloser)
	r.p = password
	if err := r.init(f, info.Size()); err != nil {
		f.Close()
		return nil, err
	}
	r.f = f

	return r, nil
}

func OpenReader(name string) (*ReadCloser, error) {
	return OpenReaderWithPassword(name, "")
}

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

func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	return NewReaderWithPassword(r, size, "")
}

func crc32Compare(b []byte, c uint32) int {
	return bytes.Compare(b, []byte{byte(0xff & (c >> 24)), byte(0xff & (c >> 16)), byte(0xff & (c >> 8)), byte(0xff & c)})
}

func readUint64(hr headerReader) (uint64, error) {
	b, err := hr.ReadByte()
	if err != nil {
		return 0, err
	}
	l := bits.LeadingZeros8(^b)

	var v uint64
	if l < 7 {
		v |= uint64(b&((1<<(8-l))-1)) << (8 * l)
	}

	for i := 0; i < l; i++ {
		b, err := hr.ReadByte()
		if err != nil {
			return 0, err
		}
		v |= uint64(b) << (8 * i)
	}

	return v, nil
}

func readBool(hr headerReader, count uint64) ([]bool, error) {
	all, err := hr.ReadByte()
	if err != nil {
		return nil, err
	}

	defined := make([]bool, count)
	if all == 0 {
		return nil, errors.New("sevenzip: TODO readBool")
	}

	for i := range defined {
		defined[i] = true
	}

	return defined, nil
}

func readSizes(hr headerReader, count uint64) ([]uint64, error) {
	sizes := make([]uint64, count)
	for i := uint64(0); i < count; i++ {
		size, err := readUint64(hr)
		if err != nil {
			return nil, err
		}
		sizes[i] = size
	}
	return sizes, nil
}

func readCRC(hr headerReader, count uint64) ([]uint32, []bool, error) {
	defined, err := readBool(hr, count)
	if err != nil {
		return nil, nil, err
	}

	crcs := make([]uint32, count)
	for i := uint64(0); i < count; i++ {
		var crc uint32
		if err := binary.Read(hr, binary.LittleEndian, &crc); err != nil {
			return nil, nil, err
		}
		crcs[i] = crc
	}

	return crcs, defined, nil
}

func readPackInfo(hr headerReader) (*packInfo, error) {
	p := new(packInfo)

	var err error
	p.position, err = readUint64(hr)
	if err != nil {
		return nil, err
	}

	p.streams, err = readUint64(hr)
	if err != nil {
		return nil, err
	}

	id, err := hr.ReadByte()
	if err != nil {
		return nil, err
	}

	if id == idSize {
		if p.size, err = readSizes(hr, p.streams); err != nil {
			return nil, err
		}

		id, err = hr.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idCRC {
		if p.digest, p.defined, err = readCRC(hr, p.streams); err != nil {
			return nil, err
		}

		id, err = hr.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id != idEnd {
		return nil, errUnexpectedID
	}

	return p, nil
}

func readCoder(hr headerReader) (*coder, error) {
	c := new(coder)

	v, err := hr.ReadByte()
	if err != nil {
		return nil, err
	}

	c.id = make([]byte, v&0xf)
	if n, err := hr.Read(c.id); err != nil || n != int(v&0xf) {
		if err != nil {
			return nil, err
		}
		return nil, errIncompleteRead
	}

	if v&0x10 != 0 {
		c.in, err = readUint64(hr)
		if err != nil {
			return nil, err
		}

		c.out, err = readUint64(hr)
		if err != nil {
			return nil, err
		}
	} else {
		c.in, c.out = 1, 1
	}

	if v&0x20 != 0 {
		size, err := readUint64(hr)
		if err != nil {
			return nil, err
		}

		c.properties = make([]byte, size)
		if n, err := hr.Read(c.properties); err != nil || n != int(size) {
			if err != nil {
				return nil, err
			}
			return nil, errIncompleteRead
		}
	}

	return c, nil
}

func readFolder(hr headerReader) (*folder, error) {
	f := new(folder)

	coders, err := readUint64(hr)
	if err != nil {
		return nil, err
	}

	in, out := uint64(0), uint64(0)

	f.coder = make([]*coder, coders)
	for i := uint64(0); i < coders; i++ {
		if f.coder[i], err = readCoder(hr); err != nil {
			return nil, err
		}
		in += f.coder[i].in
		out += f.coder[i].out
	}

	bindPairs := out - 1

	f.bindPair = make([]*bindPair, bindPairs)
	for i := uint64(0); i < bindPairs; i++ {
		in, err := readUint64(hr)
		if err != nil {
			return nil, err
		}

		out, err := readUint64(hr)
		if err != nil {
			return nil, err
		}

		f.bindPair[i] = &bindPair{
			in:  in,
			out: out,
		}
	}

	f.packedStreams = in - bindPairs

	if f.packedStreams == 1 {
		f.packed = []uint64{}
		for i := uint64(0); i < in; i++ {
			if f.findInBindPair(i) == nil {
				f.packed = append(f.packed, i)
			}
		}
	} else {
		f.packed = make([]uint64, f.packedStreams)
		for i := uint64(0); i < f.packedStreams; i++ {
			if f.packed[i], err = readUint64(hr); err != nil {
				return nil, err
			}
		}
	}

	return f, nil
}

func readUnpackInfo(hr headerReader) (*unpackInfo, error) {
	u := new(unpackInfo)

	if id, err := hr.ReadByte(); err != nil || id != idFolder {
		if err != nil {
			return nil, err
		}
		return nil, errUnexpectedID
	}

	folders, err := readUint64(hr)
	if err != nil {
		return nil, err
	}

	external, err := hr.ReadByte()
	if err != nil {
		return nil, err
	}

	if external > 0 {
		_, err := readUint64(hr)
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
		if u.folder[i], err = readFolder(hr); err != nil {
			return nil, err
		}
	}

	if id, err := hr.ReadByte(); err != nil || id != idCodersUnpackSize {
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
			if f.size[i], err = readUint64(hr); err != nil {
				return nil, err
			}
		}
	}

	id, err := hr.ReadByte()
	if err != nil {
		return nil, err
	}

	if id == idCRC {
		if u.digest, u.defined, err = readCRC(hr, folders); err != nil {
			return nil, err
		}

		id, err = hr.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id != idEnd {
		return nil, errUnexpectedID
	}

	return u, nil
}

func readSubStreamsInfo(hr headerReader, folder []*folder) (*subStreamsInfo, error) {
	s := new(subStreamsInfo)

	id, err := hr.ReadByte()
	if err != nil {
		return nil, err
	}

	s.streams = make([]uint64, len(folder))
	if id == idNumUnpackStream {
		for i := range s.streams {
			if s.streams[i], err = readUint64(hr); err != nil {
				return nil, err
			}
		}

		id, err = hr.ReadByte()
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
				if s.size[k], err = readUint64(hr); err != nil {
					return nil, err
				}
				total += s.size[k]
				k++
			}
			s.size[k] = folder[i].unpackSize() - total
			k++
		}

		id, err = hr.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idCRC {
		if s.digest, s.defined, err = readCRC(hr, files); err != nil {
			return nil, err
		}

		id, err = hr.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id != idEnd {
		return nil, errUnexpectedID
	}

	return s, nil
}

func readStreamsInfo(hr headerReader) (*streamsInfo, error) {
	s := new(streamsInfo)

	id, err := hr.ReadByte()
	if err != nil {
		return nil, err
	}

	if id == idPackInfo {
		if s.packInfo, err = readPackInfo(hr); err != nil {
			return nil, err
		}

		id, err = hr.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idUnpackInfo {
		if s.unpackInfo, err = readUnpackInfo(hr); err != nil {
			return nil, err
		}

		id, err = hr.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idSubStreamsInfo {
		if s.subStreamsInfo, err = readSubStreamsInfo(hr, s.unpackInfo.folder); err != nil {
			return nil, err
		}

		id, err = hr.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id != idEnd {
		return nil, errUnexpectedID
	}

	return s, nil
}

func readTimes(hr headerReader, count, length uint64) ([]time.Time, error) {
	_, err := readBool(hr, count)
	if err != nil {
		return nil, err
	}

	external, err := hr.ReadByte()
	if err != nil {
		return nil, err
	}

	if external > 0 {
		_, err := readUint64(hr)
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
		if err := binary.Read(hr, binary.LittleEndian, &ft); err != nil {
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

func readNames(hr headerReader, count, length uint64) ([]string, error) {
	external, err := hr.ReadByte()
	if err != nil {
		return nil, err
	}

	if external > 0 {
		_, err := readUint64(hr)
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
	scanner := bufio.NewScanner(transform.NewReader(io.LimitReader(hr, int64(length-1)), utf16le.NewDecoder()))
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

func readAttributes(hr headerReader, count, length uint64) ([]uint32, error) {
	_, err := readBool(hr, count)
	if err != nil {
		return nil, err
	}

	external, err := hr.ReadByte()
	if err != nil {
		return nil, err
	}

	if external > 0 {
		_, err := readUint64(hr)
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
		if err := binary.Read(hr, binary.LittleEndian, &attributes[i]); err != nil {
			return nil, err
		}
	}

	return attributes, nil
}

func readFilesInfo(hr headerReader) (*filesInfo, error) {
	f := new(filesInfo)

	files, err := readUint64(hr)
	if err != nil {
		return nil, err
	}
	f.file = make([]file, files)

	for {
		property, err := hr.ReadByte()
		if err != nil {
			return nil, err
		}

		if property == idEnd {
			break
		}

		length, err := readUint64(hr)
		if err != nil {
			return nil, err
		}

		switch property {
		case idEmptyStream:
			return nil, errors.New("sevenzip: TODO idEmptyStream")
		case idEmptyFile:
			return nil, errors.New("sevenzip: TODO idEmptyFile")
		case idCTime:
			times, err := readTimes(hr, files, length)
			if err != nil {
				return nil, err
			}

			for i, t := range times {
				f.file[i].ctime = t
			}
		case idATime:
			times, err := readTimes(hr, files, length)
			if err != nil {
				return nil, err
			}

			for i, t := range times {
				f.file[i].atime = t
			}
		case idMTime:
			times, err := readTimes(hr, files, length)
			if err != nil {
				return nil, err
			}

			for i, t := range times {
				f.file[i].mtime = t
			}
		case idName:
			names, err := readNames(hr, files, length)
			if err != nil {
				return nil, err
			}

			for i, n := range names {
				f.file[i].name = n
			}
		case idWinAttributes:
			attributes, err := readAttributes(hr, files, length)
			if err != nil {
				return nil, err
			}

			// FIXME
			for i, a := range attributes {
				fmt.Println(i, a)
			}
		case idStartPos:
			return nil, errors.New("sevenzip: TODO idStartPos")
		case idDummy:
			if _, err := io.CopyN(ioutil.Discard, hr, int64(length)); err != nil {
				return nil, err
			}
		default:
			return nil, errUnexpectedID
		}
	}

	return f, nil
}

func readHeader(hr headerReader) (*header, error) {
	h := new(header)

	id, err := hr.ReadByte()
	if err != nil {
		return nil, err
	}

	if id == idArchiveProperties {
		return nil, errors.New("sevenzip: TODO idArchiveProperties")

		id, err = hr.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idAdditionalStreamsInfo {
		return nil, errors.New("sevenzip: TODO idAdditionalStreamsInfo")

		id, err = hr.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idMainStreamsInfo {
		if h.streamsInfo, err = readStreamsInfo(hr); err != nil {
			return nil, err
		}

		id, err = hr.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id == idFilesInfo {
		if h.filesInfo, err = readFilesInfo(hr); err != nil {
			return nil, err
		}

		id, err = hr.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	if id != idEnd {
		return nil, errUnexpectedID
	}

	return h, nil
}

func (z *Reader) folderReader(si *streamsInfo, f int) (io.ReadCloser, uint32, error) {
	// Create a SectionReader covering all of the streams data
	sr := io.NewSectionReader(z.r, z.start, z.end)

	// Seek to where the folder in this particular stream starts
	if _, err := sr.Seek(si.FolderOffset(f), io.SeekStart); err != nil {
		return nil, 0, err
	}

	// Adding buffering here makes a noticeable performance difference
	return si.FolderReader(ioutil.NopCloser(bufio.NewReader(sr)), f, z.p)
}

func (z *Reader) init(r io.ReaderAt, size int64) error {
	h := crc32.NewIEEE()
	tra := plumbing.TeeReaderAt(r, h)
	sr := io.NewSectionReader(tra, 0, size) // Will only read first 32 bytes

	var sh signatureHeader
	if err := binary.Read(sr, binary.LittleEndian, &sh); err != nil {
		return err
	}

	if bytes.Compare(sh.Signature[:], signature[:]) != 0 {
		return errFormat
	}

	z.r = r

	h.Reset()

	var err error
	var start startHeader
	if err = binary.Read(sr, binary.LittleEndian, &start); err != nil {
		return err
	}

	// CRC of the start header should match
	if crc32Compare(h.Sum(nil), sh.CRC) != 0 {
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

	var header *header
	var streamsInfo *streamsInfo

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
	if crc32Compare(h.Sum(nil), start.CRC) != 0 {
		return errChecksum
	}

	// If the header was encoded we should have sufficient information now
	// to decode it
	if id == idEncodedHeader && streamsInfo != nil {
		spew.Dump(streamsInfo)

		// XXX Assert there's only one folder?

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

		if cr, ok := fr.(checksumReadCloser); ok && crc != 0 {
			if crc32Compare(cr.Checksum(), crc) != 0 {
				return errChecksum
			}
		}
	}

	spew.Dump(header)

	return nil
}

func (rc *ReadCloser) Close() error {
	return rc.f.Close()
}
