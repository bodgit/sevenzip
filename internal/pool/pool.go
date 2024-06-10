package pool

import (
	"runtime"
	"sort"
	"sync"

	"github.com/bodgit/sevenzip/internal/util"
	lru "github.com/hashicorp/golang-lru/v2"
)

// Pooler is the interface implemented by a pool.
type Pooler interface {
	Get(int64) (util.SizeReadSeekCloser, bool)
	Put(int64, util.SizeReadSeekCloser) (bool, error)
}

// Constructor is the function prototype used to instantiate a pool.
type Constructor func() (Pooler, error)

type noopPool struct{}

// NewNoopPool returns a Pooler that doesn't actually pool anything.
func NewNoopPool() (Pooler, error) {
	return new(noopPool), nil
}

func (noopPool) Get(_ int64) (util.SizeReadSeekCloser, bool) {
	return nil, false
}

func (noopPool) Put(_ int64, rc util.SizeReadSeekCloser) (bool, error) {
	return false, rc.Close()
}

type pool struct {
	mutex sync.Mutex
	errs  chan error
	cache *lru.Cache[int64, util.SizeReadSeekCloser]
}

// NewPool returns a Pooler that uses a LRU strategy to maintain a fixed pool
// of util.SizeReadSeekCloser's keyed by their stream offset.
func NewPool() (Pooler, error) {
	errs := make(chan error)

	cache, err := lru.NewWithEvict[int64, util.SizeReadSeekCloser](
		runtime.NumCPU(),
		func(_ int64, value util.SizeReadSeekCloser) {
			if err := value.Close(); err != nil {
				errs <- err
			}
		})
	if err != nil {
		return nil, err
	}

	return &pool{
		errs:  errs,
		cache: cache,
	}, nil
}

func (p *pool) Get(offset int64) (util.SizeReadSeekCloser, bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if reader, ok := p.cache.Get(offset); ok {
		_ = p.cache.RemoveWithoutEvict(offset)

		return reader, true
	}

	// Sort keys in descending order
	keys := p.cache.Keys()
	sort.Slice(keys, func(i, j int) bool { return keys[i] > keys[j] })

	for _, k := range keys {
		// First key less than offset is the closest
		if k < offset {
			reader, _ := p.cache.Get(k)
			_ = p.cache.RemoveWithoutEvict(k)

			return reader, true
		}
	}

	return nil, false
}

func (p *pool) Put(offset int64, rc util.SizeReadSeekCloser) (bool, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	_, ok := p.cache.ContainsOrAdd(offset, rc)

	select {
	case err := <-p.errs:
		return ok, err
	default:
	}

	return ok, nil
}
