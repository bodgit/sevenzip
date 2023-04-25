package sevenzip_test

import (
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/bodgit/sevenzip"
	"github.com/bodgit/sevenzip/internal/util"
	"github.com/stretchr/testify/assert"
)

func readArchive(t *testing.T, r *sevenzip.ReadCloser) {
	t.Helper()

	h := crc32.NewIEEE()

	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()

		h.Reset()

		if _, err := io.Copy(h, rc); err != nil {
			t.Fatal(err)
		}

		rc.Close()

		if !util.CRC32Equal(h.Sum(nil), f.CRC32) {
			t.Fatal(errors.New("CRC doesn't match"))
		}
	}
}

//nolint:funlen
func TestOpenReader(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name, file string
		volumes    []string
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
			volumes: []string{
				"multi.7z.001",
				"multi.7z.002",
				"multi.7z.003",
				"multi.7z.004",
				"multi.7z.005",
				"multi.7z.006",
			},
		},
		{
			name: "empty streams and files",
			file: "empty.7z",
		},
		{
			name: "bcj2",
			file: "bcj2.7z",
		},
		{
			name: "bzip2",
			file: "bzip2.7z",
		},
		{
			name: "copy",
			file: "copy.7z",
		},
		{
			name: "deflate",
			file: "deflate.7z",
		},
		{
			name: "delta",
			file: "delta.7z",
		},
		{
			name: "lzma",
			file: "lzma.7z",
		},
		{
			name: "lzma2",
			file: "lzma2.7z",
		},
		{
			name: "complex",
			file: "lzma1900.7z",
		},
		{
			name: "lz4",
			file: "lz4.7z",
		},
		{
			name: "brotli",
			file: "brotli.7z",
		},
		{
			name: "zstd",
			file: "zstd.7z",
		},
		{
			name: "sfx",
			file: "sfx.exe",
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

			volumes := []string{}

			if table.volumes != nil {
				for _, v := range table.volumes {
					volumes = append(volumes, filepath.Join("testdata", v))
				}
			} else {
				volumes = append(volumes, filepath.Join("testdata", table.file))
			}

			assert.Equal(t, volumes, r.Volumes())

			readArchive(t, r)
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
		{
			name:     "issue 75",
			file:     "7zcracker.7z",
			password: "876",
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

			readArchive(t, r)
		})
	}
}

func TestFS(t *testing.T) {
	t.Parallel()

	r, err := sevenzip.OpenReader(filepath.Join("testdata", "lzma1900.7z"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if err := fstest.TestFS(r, "Asm/arm/7zCrcOpt.asm", "bin/x64/7zr.exe"); err != nil {
		t.Fatal(err)
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

func BenchmarkComplex(b *testing.B) {
	benchmarkArchive(b, "lzma1900.7z")
}

func BenchmarkLZ4(b *testing.B) {
	benchmarkArchive(b, "lz4.7z")
}

func BenchmarkBrotli(b *testing.B) {
	benchmarkArchive(b, "brotli.7z")
}

func BenchmarkZstandard(b *testing.B) {
	benchmarkArchive(b, "zstd.7z")
}
