// Package pool implements the reader pooling.
package pool

import (
	"container/list"
	"errors"
	"runtime"
	"sort"
	"sync"

	"github.com/bodgit/sevenzip/internal/util"
)

// Pooler is the interface implemented by a pool.
type Pooler interface {
	Get(offset int64) (util.SizeReadSeekCloser, bool)
	Put(offset int64, rc util.SizeReadSeekCloser) (bool, error)
	// Close closes any pooled readers, any readers subsequently passed to
	// Put are closed immediately.
	Close() error
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
	return false, rc.Close() //nolint:wrapcheck
}

func (noopPool) Close() error {
	return nil
}

type pool struct {
	mutex     sync.Mutex
	size      int
	closed    bool
	evictList *list.List
	items     map[int64]*list.Element
}

type entry struct {
	key   int64
	value util.SizeReadSeekCloser
}

// NewPool returns a Pooler that uses a LRU strategy to maintain a fixed pool
// of util.SizeReadSeekCloser's keyed by their stream offset.
func NewPool() (Pooler, error) {
	return &pool{
		size:      runtime.NumCPU(),
		evictList: list.New(),
		items:     make(map[int64]*list.Element),
	}, nil
}

func (p *pool) Get(offset int64) (util.SizeReadSeekCloser, bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.closed {
		return nil, false
	}

	if ent, ok := p.items[offset]; ok {
		_ = p.removeElement(ent, false)

		return ent.Value.(*entry).value, true //nolint:forcetypeassert
	}

	// Sort keys in descending order
	keys := p.keys()
	sort.Slice(keys, func(i, j int) bool { return keys[i] > keys[j] })

	for _, k := range keys {
		// First key less than offset is the closest
		if k < offset {
			ent := p.items[k]
			_ = p.removeElement(ent, false)

			return ent.Value.(*entry).value, true //nolint:forcetypeassert
		}
	}

	return nil, false
}

func (p *pool) Put(offset int64, rc util.SizeReadSeekCloser) (bool, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Can't pool it if the pool is closed or there's already a reader at
	// this offset
	if _, ok := p.items[offset]; ok || p.closed {
		return false, rc.Close() //nolint:wrapcheck
	}

	ent := &entry{offset, rc}
	entry := p.evictList.PushFront(ent)
	p.items[offset] = entry

	var err error

	evict := p.evictList.Len() > p.size
	if evict {
		err = p.removeOldest()
	}

	return evict, err
}

func (p *pool) Close() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.closed = true

	var errs []error

	for p.evictList.Len() > 0 {
		errs = append(errs, p.removeOldest())
	}

	return errors.Join(errs...)
}

func (p *pool) keys() []int64 {
	keys := make([]int64, len(p.items))
	i := 0

	for ent := p.evictList.Back(); ent != nil; ent = ent.Prev() {
		keys[i] = ent.Value.(*entry).key //nolint:forcetypeassert
		i++
	}

	return keys
}

func (p *pool) removeOldest() error {
	if ent := p.evictList.Back(); ent != nil {
		return p.removeElement(ent, true)
	}

	return nil
}

func (p *pool) removeElement(e *list.Element, cb bool) error {
	p.evictList.Remove(e)
	kv := e.Value.(*entry) //nolint:forcetypeassert
	delete(p.items, kv.key)

	if cb {
		return kv.value.Close() //nolint:wrapcheck
	}

	return nil
}
