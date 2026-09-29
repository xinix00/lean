package leannet

// budget.go implements leannet's single memory control. Connection buffers
// reserve from Config.Budget as they grow and return capacity on close, so
// memory follows use rather than configuration. See doc.go.

import "sync"

// budget tracks capacity; callers allocate the actual bytes.
type budget struct {
	mu    sync.Mutex
	total int
	used  int
}

// reserve claims n bytes if available. Callers may retry smaller or fail, but
// never wait silently for memory.
func (b *budget) reserve(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || b.used+n > b.total {
		return false
	}
	b.used += n
	return true
}

// release returns n bytes. Releasing more than reserved panics because it would
// invalidate the budget guarantee.
func (b *budget) release(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > b.used {
		panic("leannet: budget release exceeds reserved")
	}
	b.used -= n
}

// free returns a snapshot for tuning and telemetry; reserve is authoritative.
func (b *budget) free() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total - b.used
}
