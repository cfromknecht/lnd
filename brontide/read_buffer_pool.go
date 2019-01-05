package brontide

import (
	"time"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/queue"
)

const (
	// DefaultGCInterval is the default interval that the WriteBufferPool
	// will perform a sweep to see which expired buffers can be released to
	// the runtime.
	DefaultGCInterval = 15 * time.Second

	// DefaultExpiryInterval is the default, minimum interval that must
	// elapse before a WriteBuffer will be released. The maximum time before
	// the buffer can be released is equal to the expiry interval plus the
	// gc interval.
	DefaultExpiryInterval = 30 * time.Second

	// readBufferSize represents the size of the maximum message that can be
	// read off  the wire by brontide. The buffer is used to hold the
	// ciphertext while the  brontide state machine decrypts the message.
	readBufferSize = lnwire.MaxMessagePayload + macSize
)

// ReadBuffer is a static byte array sized to the maximum-allowed message size,
// plus 16 bytes for the MAC.
type ReadBuffer [readBufferSize]byte

// Recycle zeroes the ReadBuffer, making it fresh for another use.
// Zeroing the buffer using a logarithmic number of calls to the optimized copy
// method.  Benchmarking shows this to be ~30 times faster than a for loop that
// sets each index to 0 for this buffer size. Inspired by:
// https://stackoverflow.com/questions/30614165/is-there-analog-of-memset-in-go
func (b *ReadBuffer) Recycle() {
	b[0] = 0
	for i := 1; i < readBufferSize; i *= 2 {
		copy(b[i:], b[:i])
	}
}

// newRecyclableReadBuffer is a constructor that returns a ReadBuffer as a
// queue.Recycler.
func newRecyclableReadBuffer() queue.Recycler {
	return new(ReadBuffer)
}

// A compile-time constraint to ensure that *ReadBuffer implements the
// queue.Recycler interface.
var _ queue.Recycler = (*ReadBuffer)(nil)

// ReadBufferPool acts as a global pool of ReadBuffers, that dynamically
// allocates and reclaims buffers in response to load.
type ReadBufferPool struct {
	pool *queue.GCQueue
}

// NewReadBufferPool returns a freshly instantiated ReadBufferPool, using the
// given gcInterval and expieryInterval.
func NewReadBufferPool(
	gcInterval, expiryInterval time.Duration) *ReadBufferPool {

	return &ReadBufferPool{
		pool: queue.NewGCQueue(
			newRecyclableReadBuffer, gcInterval, expiryInterval,
		),
	}
}

// Take returns a fresh ReadBuffer to the caller.
func (p *ReadBufferPool) Take() *ReadBuffer {
	return p.pool.Take().(*ReadBuffer)
}

// Return returns the ReadBuffer to the pool, so that it can be cycled or
// released.
func (p *ReadBufferPool) Return(buf *ReadBuffer) {
	p.pool.Return(buf)
}

// readBufferPool is a singleton instance of the buffer pool, used to conserve
// memory allocations due to read buffers across the entire brontide package.
var readBufferPool = NewReadBufferPool(DefaultGCInterval, DefaultExpiryInterval)
