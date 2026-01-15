package pool

import (
	"sync"
)

// We use 32KB buffers to handle large reads and crypto overhead
const BufferSize = 32 * 1024

var bufferPool = sync.Pool{
	New: func() interface{} {
		// return pointer to array to avoid allocation when triggering New
		b := make([]byte, BufferSize)
		return &b
	},
}

// Get returns a byte slice of capacity BufferSize.
// The length is set to BufferSize.
func Get() []byte {
	return *bufferPool.Get().(*[]byte)
}

// Put returns the buffer to the pool.
func Put(b []byte) {
	if cap(b) != BufferSize {
		// Don't pool buffers of wrong size
		return
	}
	// Reset to full capacity before putting back (though slices are just headers)
	// We store pointer to the backing array basically.
	// We need to pass a pointer to sync.Pool to avoid allocs on interface conversion if we were using array,
	// but here we used []byte.
	// Actually better:
	b = b[:cap(b)]
	bufferPool.Put(&b)
}
