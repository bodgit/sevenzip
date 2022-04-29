package sevenzip

import (
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"path/filepath"
	"testing"
)

func TestOpenReader(t *testing.T) {
	tables := map[string]struct {
		file string
	}{
		"no header compression": {
			file: "t0.7z",
		},
		"with header compression": {
			file: "t1.7z",
		},
		"multiple volume": {
			file: "multi.7z.001",
		},
		"empty streams and files": {
			file: "empty.7z",
		},
	}

	for name, table := range tables {
		t.Run(name, func(t *testing.T) {
			r, err := OpenReader(filepath.Join("testdata", table.file))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
		})
	}
}

func TestOpenReaderWithPassword(t *testing.T) {
	tables := map[string]struct {
		file     string
		password string
	}{
		"no header compression": {
			file:     "t2.7z",
			password: "password",
		},
		"with header compression": {
			file:     "t3.7z",
			password: "password",
		},
	}

	for name, table := range tables {
		t.Run(name, func(t *testing.T) {
			r, err := OpenReaderWithPassword(filepath.Join("testdata", table.file), table.password)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
		})
	}
}

func ExampleOpenReader() {
	r, err := OpenReader(filepath.Join("testdata", "multi.7z.001"))
	if err != nil {
		panic(err)
	}
	defer r.Close()

	for _, file := range r.File {
		fmt.Println(file.Name)
	}
	// Output: 01
	// 02
	// 03
	// 04
	// 05
	// 06
	// 07
	// 08
	// 09
	// 10
}

func benchmarkArchive(file string, b *testing.B) {
	h := crc32.NewIEEE()
	for n := 0; n < b.N; n++ {
		r, err := OpenReader(filepath.Join("testdata", file))
		if err != nil {
			b.Fatal(err)
		}
		defer r.Close()
		for _, f := range r.File {
			rc, err := f.Open()
			if err != nil {
				b.Fatal(err)
			}
			defer rc.Close()
			h.Reset()
			if _, err := io.Copy(h, rc); err != nil {
				b.Fatal(err)
			}
			rc.Close()
			if crc32Compare(h.Sum(nil), f.CRC32) != 0 {
				b.Fatal(errors.New("CRC doesn't match"))
			}
		}
		r.Close()
	}
}

func BenchmarkBzip2(b *testing.B) {
	benchmarkArchive("bzip2.7z", b)
}

func BenchmarkCopy(b *testing.B) {
	benchmarkArchive("copy.7z", b)
}

func BenchmarkDeflate(b *testing.B) {
	benchmarkArchive("deflate.7z", b)
}

func BenchmarkDelta(b *testing.B) {
	benchmarkArchive("delta.7z", b)
}

func BenchmarkLZMA(b *testing.B) {
	benchmarkArchive("lzma.7z", b)
}

func BenchmarkLZMA2(b *testing.B) {
	benchmarkArchive("lzma2.7z", b)
}

func BenchmarkBCJ2(b *testing.B) {
	benchmarkArchive("bcj2.7z", b)
}
