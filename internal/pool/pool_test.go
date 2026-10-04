package pool_test

import (
	"io"
	"runtime"
	"testing"

	"github.com/bodgit/sevenzip/internal/pool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type readCloser struct {
	closed int
}

func (rc *readCloser) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (rc *readCloser) Seek(_ int64, _ int) (int64, error) { return 0, nil }
func (rc *readCloser) Size() int64                        { return 0 }

func (rc *readCloser) Close() error {
	rc.closed++

	return nil
}

func TestNoopPool(t *testing.T) {
	t.Parallel()

	p, err := pool.NewNoopPool()
	require.NoError(t, err)

	rc := new(readCloser)

	_, err = p.Put(0, rc)
	require.NoError(t, err)
	assert.Equal(t, 1, rc.closed)

	got, ok := p.Get(0)
	assert.False(t, ok)
	assert.Nil(t, got)

	require.NoError(t, p.Close())
}

func TestPoolGet(t *testing.T) {
	t.Parallel()

	p, err := pool.NewPool()
	require.NoError(t, err)

	rc1, rc2 := new(readCloser), new(readCloser)

	_, err = p.Put(10, rc1)
	require.NoError(t, err)

	_, err = p.Put(20, rc2)
	require.NoError(t, err)

	// Nothing is behind offset 5
	_, ok := p.Get(5)
	assert.False(t, ok)

	// Closest reader behind offset 15
	got, ok := p.Get(15)
	assert.True(t, ok)
	assert.Same(t, rc1, got)

	// Exact match
	got, ok = p.Get(20)
	assert.True(t, ok)
	assert.Same(t, rc2, got)

	assert.Zero(t, rc1.closed)
	assert.Zero(t, rc2.closed)
}

func TestPoolPutDuplicate(t *testing.T) {
	t.Parallel()

	p, err := pool.NewPool()
	require.NoError(t, err)

	rc1, rc2 := new(readCloser), new(readCloser)

	_, err = p.Put(10, rc1)
	require.NoError(t, err)

	// A second reader at the same offset can't be pooled so must be closed
	_, err = p.Put(10, rc2)
	require.NoError(t, err)
	assert.Zero(t, rc1.closed)
	assert.Equal(t, 1, rc2.closed)

	got, ok := p.Get(10)
	assert.True(t, ok)
	assert.Same(t, rc1, got)
}

func TestPoolEvict(t *testing.T) {
	t.Parallel()

	p, err := pool.NewPool()
	require.NoError(t, err)

	rcs := make([]*readCloser, runtime.NumCPU()+1)
	for i := range rcs {
		rcs[i] = new(readCloser)

		evicted, err := p.Put(int64(i), rcs[i])
		require.NoError(t, err)
		assert.Equal(t, i == len(rcs)-1, evicted)
	}

	// The oldest reader is evicted and closed
	assert.Equal(t, 1, rcs[0].closed)

	for _, rc := range rcs[1:] {
		assert.Zero(t, rc.closed)
	}
}

func TestPoolClose(t *testing.T) {
	t.Parallel()

	p, err := pool.NewPool()
	require.NoError(t, err)

	rc1, rc2 := new(readCloser), new(readCloser)

	_, err = p.Put(10, rc1)
	require.NoError(t, err)

	_, err = p.Put(20, rc2)
	require.NoError(t, err)

	// Closing the pool closes all pooled readers
	require.NoError(t, p.Close())
	assert.Equal(t, 1, rc1.closed)
	assert.Equal(t, 1, rc2.closed)

	_, ok := p.Get(20)
	assert.False(t, ok)

	// Readers returned after the pool is closed are closed immediately
	rc3 := new(readCloser)

	_, err = p.Put(30, rc3)
	require.NoError(t, err)
	assert.Equal(t, 1, rc3.closed)

	_, ok = p.Get(30)
	assert.False(t, ok)

	// Closing again is harmless
	require.NoError(t, p.Close())
	assert.Equal(t, 1, rc1.closed)
	assert.Equal(t, 1, rc2.closed)
}
