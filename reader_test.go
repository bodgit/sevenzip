package sevenzip_test

import (
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"testing/fstest"
	"testing/iotest"

	"github.com/bodgit/sevenzip"
	"github.com/bodgit/sevenzip/internal/util"
	"github.com/hashicorp/go-multierror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func reader(r io.Reader) io.Reader {
	return r
}

var errCRCMismatch = errors.New("CRC doesn't match")

func extractFile(tb testing.TB, r io.Reader, h hash.Hash, f *sevenzip.File) error {
	tb.Helper()

	h.Reset()

	if _, err := io.Copy(h, r); err != nil {
		return fmt.Errorf("error extracting file: %w", err)
	}

	if f.UncompressedSize > 0 && f.CRC32 == 0 {
		tb.Log("archive member", f.Name, "has no CRC")

		return nil
	}

	if !util.CRC32Equal(h.Sum(nil), f.CRC32) {
		return errCRCMismatch
	}

	return nil
}

//nolint:lll
func extractArchive(tb testing.TB, r *sevenzip.ReadCloser, stream int, h hash.Hash, fn func(io.Reader) io.Reader, optimised bool) (err error) {
	tb.Helper()

	for _, f := range r.File {
		if stream >= 0 && f.Stream != stream {
			continue
		}

		var rc io.ReadCloser

		rc, err = f.Open()
		if err != nil {
			return fmt.Errorf("error opening file: %w", err)
		}

		defer func() {
			err = multierror.Append(err, rc.Close()).ErrorOrNil()
		}()

		if err = extractFile(tb, fn(rc), h, f); err != nil {
			return err
		}

		if optimised {
			if err = rc.Close(); err != nil {
				return fmt.Errorf("error closing: %w", err)
			}
		}
	}

	return nil
}

//nolint:funlen
func TestOpenReader(t *testing.T) {
	t.Parallel()

	tables := []struct {
		name, file string
		volumes    []string
		err        error
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
			name: "empty2",
			file: "empty2.7z",
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
		{
			name: "bcj",
			file: "bcj.7z",
		},
		{
			name: "ppc",
			file: "ppc.7z",
		},
		{
			name: "arm",
			file: "arm.7z",
		},
		{
			name: "sparc",
			file: "sparc.7z",
		},
		{
			name: "issue 87",
			file: "issue87.7z",
		},
		{
			name: "issue 112",
			file: "file_and_empty.7z",
		},
		{
			name: "issue 113",
			file: "COMPRESS-492.7z",
			err:  sevenzip.ErrMissingUnpackInfo,
		},
	}

	for _, table := range tables {
		table := table

		t.Run(table.name, func(t *testing.T) {
			t.Parallel()

			r, err := sevenzip.OpenReader(filepath.Join("testdata", table.file))
			if table.err == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, table.err)

				return
			}

			defer func() {
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
			}()

			volumes := []string{}

			if table.volumes != nil {
				for _, v := range table.volumes {
					volumes = append(volumes, filepath.Join("testdata", v))
				}
			} else {
				volumes = append(volumes, filepath.Join("testdata", table.file))
			}

			assert.Equal(t, volumes, r.Volumes())

			if err := extractArchive(t, r, -1, crc32.NewIEEE(), iotest.OneByteReader, true); err != nil {
				t.Fatal(err)
			}
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
			name:     "unencrypted headers compressed files",
			file:     "t4.7z",
			password: "password",
		},
		{
			name:     "unencrypted headers uncompressed files",
			file:     "t5.7z",
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

			defer func() {
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
			}()

			if err := extractArchive(t, r, -1, crc32.NewIEEE(), iotest.OneByteReader, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOpenReaderWithWrongPassword(t *testing.T) {
	t.Parallel()

	t.Run("encrypted headers", func(t *testing.T) {
		t.Parallel()

		_, err := sevenzip.OpenReaderWithPassword(filepath.Join("testdata", "t2.7z"), "notpassword")

		var e *sevenzip.ReadError
		if assert.ErrorAs(t, err, &e) {
			assert.True(t, e.Encrypted)
		}
	})

	t.Run("unencrypted headers compressed files", func(t *testing.T) {
		t.Parallel()

		r, err := sevenzip.OpenReaderWithPassword(filepath.Join("testdata", "t4.7z"), "notpassword")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, r.Close())
		}()

		err = extractArchive(t, r, -1, crc32.NewIEEE(), iotest.OneByteReader, true)

		var e *sevenzip.ReadError
		if assert.ErrorAs(t, err, &e) {
			assert.True(t, e.Encrypted)
		}
	})

	t.Run("unencrypted headers uncompressed files", func(t *testing.T) {
		t.Parallel()

		r, err := sevenzip.OpenReaderWithPassword(filepath.Join("testdata", "t5.7z"), "notpassword")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, r.Close())
		}()

		err = extractArchive(t, r, -1, crc32.NewIEEE(), iotest.OneByteReader, true)
		assert.ErrorIs(t, err, errCRCMismatch)
	})
}

func TestFS(t *testing.T) {
	t.Parallel()

	r, err := sevenzip.OpenReader(filepath.Join("testdata", "lzma1900.7z"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	if err := fstest.TestFS(r, "Asm/arm/7zCrcOpt.asm", "bin/x64/7zr.exe"); err != nil {
		t.Fatal(err)
	}
}

func ExampleOpenReader() {
	r, err := sevenzip.OpenReader(filepath.Join("testdata", "multi.7z.001"))
	if err != nil {
		panic(err)
	}

	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

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

func benchmarkArchiveParallel(b *testing.B, file string) {
	b.Helper()

	for n := 0; n < b.N; n++ {
		r, err := sevenzip.OpenReader(filepath.Join("testdata", file))
		if err != nil {
			b.Fatal(err)
		}

		var once sync.Once

		f := func() {
			if err := r.Close(); err != nil {
				b.Fatal(err)
			}
		}

		defer once.Do(f)

		streams := make(map[int]struct{}, len(r.File))

		for _, f := range r.File {
			streams[f.Stream] = struct{}{}
		}

		eg := new(errgroup.Group)
		eg.SetLimit(runtime.NumCPU())

		for stream := range streams {
			stream := stream

			eg.Go(func() error {
				return extractArchive(b, r, stream, crc32.NewIEEE(), reader, true)
			})
		}

		if err := eg.Wait(); err != nil {
			b.Fatal(err)
		}

		once.Do(f)
	}
}

func benchmarkArchiveNaiveParallel(b *testing.B, file string, workers int) {
	b.Helper()

	for n := 0; n < b.N; n++ {
		r, err := sevenzip.OpenReader(filepath.Join("testdata", file))
		if err != nil {
			b.Fatal(err)
		}

		var once sync.Once

		f := func() {
			if err := r.Close(); err != nil {
				b.Fatal(err)
			}
		}

		defer once.Do(f)

		eg := new(errgroup.Group)
		eg.SetLimit(workers)

		for _, f := range r.File {
			f := f

			eg.Go(func() (err error) {
				var rc io.ReadCloser

				rc, err = f.Open()
				if err != nil {
					return fmt.Errorf("error opening file: %w", err)
				}

				defer func() {
					err = multierror.Append(err, rc.Close()).ErrorOrNil()
				}()

				return extractFile(b, rc, crc32.NewIEEE(), f)
			})
		}

		if err := eg.Wait(); err != nil {
			b.Fatal(err)
		}

		once.Do(f)
	}
}

func benchmarkArchive(b *testing.B, file, password string, optimised bool) {
	b.Helper()

	h := crc32.NewIEEE()

	for n := 0; n < b.N; n++ {
		r, err := sevenzip.OpenReaderWithPassword(filepath.Join("testdata", file), password)
		if err != nil {
			b.Fatal(err)
		}

		var once sync.Once

		f := func() {
			if err := r.Close(); err != nil {
				b.Fatal(err)
			}
		}

		defer once.Do(f)

		if err := extractArchive(b, r, -1, h, reader, optimised); err != nil {
			b.Fatal(err)
		}

		once.Do(f)
	}
}

func BenchmarkAES7z(b *testing.B) {
	benchmarkArchive(b, "aes7z.7z", "password", true)
}

func BenchmarkBzip2(b *testing.B) {
	benchmarkArchive(b, "bzip2.7z", "", true)
}

func BenchmarkCopy(b *testing.B) {
	benchmarkArchive(b, "copy.7z", "", true)
}

func BenchmarkDeflate(b *testing.B) {
	benchmarkArchive(b, "deflate.7z", "", true)
}

func BenchmarkDelta(b *testing.B) {
	benchmarkArchive(b, "delta.7z", "", true)
}

func BenchmarkLZMA(b *testing.B) {
	benchmarkArchive(b, "lzma.7z", "", true)
}

func BenchmarkLZMA2(b *testing.B) {
	benchmarkArchive(b, "lzma2.7z", "", true)
}

func BenchmarkBCJ2(b *testing.B) {
	benchmarkArchive(b, "bcj2.7z", "", true)
}

func BenchmarkComplex(b *testing.B) {
	benchmarkArchive(b, "lzma1900.7z", "", true)
}

func BenchmarkLZ4(b *testing.B) {
	benchmarkArchive(b, "lz4.7z", "", true)
}

func BenchmarkBrotli(b *testing.B) {
	benchmarkArchive(b, "brotli.7z", "", true)
}

func BenchmarkZstandard(b *testing.B) {
	benchmarkArchive(b, "zstd.7z", "", true)
}

func BenchmarkNaiveReader(b *testing.B) {
	benchmarkArchive(b, "lzma1900.7z", "", false)
}

func BenchmarkOptimisedReader(b *testing.B) {
	benchmarkArchive(b, "lzma1900.7z", "", true)
}

func BenchmarkNaiveParallelReader(b *testing.B) {
	benchmarkArchiveNaiveParallel(b, "lzma1900.7z", runtime.NumCPU())
}

func BenchmarkNaiveSingleParallelReader(b *testing.B) {
	benchmarkArchiveNaiveParallel(b, "lzma1900.7z", 1)
}

func BenchmarkParallelReader(b *testing.B) {
	benchmarkArchiveParallel(b, "lzma1900.7z")
}

func BenchmarkBCJ(b *testing.B) {
	benchmarkArchive(b, "bcj.7z", "", true)
}

func BenchmarkPPC(b *testing.B) {
	benchmarkArchive(b, "ppc.7z", "", true)
}

func BenchmarkARM(b *testing.B) {
	benchmarkArchive(b, "arm.7z", "", true)
}

func BenchmarkSPARC(b *testing.B) {
	benchmarkArchive(b, "sparc.7z", "", true)
}
