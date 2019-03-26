package lncfg

import "fmt"

const (
	MinEdgeCacheSize    = 5000
	MinChannelCacheSize = 1000
)

// Caches holds the configuration for various caches within lnd.
type Caches struct {
	// EdgeCacheSize is the maximum number of entries stored in lnd's edge
	// cache, which is used for efficiently rejecting gossip updates. Memory
	// usage is roughly 20b per entry.
	EdgeCacheSize int

	// ChannelCacheSize is the maximum number of entries stored in lnd's
	// channel cache, which is used reduce memory allocations in reply to
	// peers querying for gossip traffic. Memory usage is roughly 2Kb per
	// entry.
	ChannelCacheSize int
}

// Validate checks the Caches configuration for values that are too small to be
// sane.
func (c *Caches) Validate() error {
	if c.EdgeCacheSize < MinEdgeCacheSize {
		return fmt.Errorf("edge cache size %d is less than min: %d",
			c.EdgeCacheSize, MinEdgeCacheSize)
	}
	if c.ChannelCacheSize < MinChannelCacheSize {
		return fmt.Errorf("channel cache size %d is less than min: %d",
			c.ChannelCacheSize, MinChannelCacheSize)
	}

	return nil
}
