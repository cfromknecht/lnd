package brontide_test

import (
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/brontide"
)

// TestReadBufferPool verifies that the buffer pool properly resets used read
// buffers.
func TestReadBufferPool(t *testing.T) {
	const (
		gcInterval     = time.Second
		expiryInterval = 250 * time.Millisecond
	)

	bp := brontide.NewReadBufferPool(gcInterval, expiryInterval)

	// Take a fresh buffer from the pool.
	readBuf := bp.Take()

	// Dirty the buffer.
	for i := range readBuf[:] {
		readBuf[i] = 0xff
	}

	// Return the buffer to the pool.
	bp.Return(readBuf)

	// Take buffers from th epool until we find the original. We expect at
	// most two, in the event that a fresh buffer is populated after the
	// first is taken.
	for i := 0; i < 2; i++ {
		// Wait a small duration to ensure the tests are reliable, and
		// don't to active the non-blocking case unintentionally.
		<-time.After(time.Millisecond)

		// Take a buffer, skipping those whose pointer does not match
		// the one we dirtied.
		readBuf2 := bp.Take()
		if readBuf2 != readBuf {
			continue
		}

		// Finally, verify that the buffer has been properly cleaned.
		for i := range readBuf2[:] {
			if readBuf2[i] != 0 {
				t.Fatalf("buffer was not recycled")
			}
		}

		return
	}

	t.Fatalf("original buffer not found")
}
