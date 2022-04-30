package sevenzip_test

import (
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"path/filepath"
	"testing"

	"github.com/bodgit/sevenzip"
	"github.com/bodgit/sevenzip/internal/util"
)

func TestOpenReader(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name, file string
	}{
		{
			name: "no header compression",
			file: "t0.7z",
		},
		{
			name: "with header compression",
			file: "t1.7z",
		},
		{
			name: "multiple volume",
			file: "multi.7z.001",
		},
		{
			name: "empty streams and files",
			file: "empty.7z",
		},
	}

	for _, table := range tables {
		table := table

		t.Run(table.name, func(t *testing.T) {
			t.Parallel()
			r, err := sevenzip.OpenReader(filepath.Join("testdata", table.file))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
		})
	}
}

func TestOpenReaderWithPassword(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name, file, password string
	}{
		{
			name:     "no header compression",
			file:     "t2.7z",
			password: "password",
		},
		{
			name:     "with header compression",
			file:     "t3.7z",
			password: "password",
		},
	}

	for _, table := range tables {
		table := table

		t.Run(table.name, func(t *testing.T) {
			t.Parallel()
			r, err := sevenzip.OpenReaderWithPassword(filepath.Join("testdata", table.file), table.password)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
		})
	}
}

func ExampleOpenReader() {
	r, err := sevenzip.OpenReader(filepath.Join("testdata", "multi.7z.001"))
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

func benchmarkArchive(b *testing.B, file string) {
	b.Helper()

	h := crc32.NewIEEE()

	for n := 0; n < b.N; n++ {
		r, err := sevenzip.OpenReader(filepath.Join("testdata", file))
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

			if !util.CRC32Equal(h.Sum(nil), f.CRC32) {
				b.Fatal(errors.New("CRC doesn't match"))
			}
		}

		r.Close()
	}
}

func BenchmarkBzip2(b *testing.B) {
	benchmarkArchive(b, "bzip2.7z")
}

func BenchmarkCopy(b *testing.B) {
	benchmarkArchive(b, "copy.7z")
}

func BenchmarkDeflate(b *testing.B) {
	benchmarkArchive(b, "deflate.7z")
}

func BenchmarkDelta(b *testing.B) {
	benchmarkArchive(b, "delta.7z")
}

func BenchmarkLZMA(b *testing.B) {
	benchmarkArchive(b, "lzma.7z")
}

func BenchmarkLZMA2(b *testing.B) {
	benchmarkArchive(b, "lzma2.7z")
}

func BenchmarkBCJ2(b *testing.B) {
	benchmarkArchive(b, "bcj2.7z")
}
