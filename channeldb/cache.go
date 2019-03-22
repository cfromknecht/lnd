package channeldb

// edgeCacheEntry caches frequently accessed information about a channel,
// including the timestamps of its latest edge policies and whether or not the
// channel exists in the graph.
type edgeCacheEntry struct {
	upd1Time int64
	upd2Time int64
	exists   bool
}

// edgeCache is an in-memory cache used to improve the performance of
// HasChannelEdge. It caches information about the whether or channel exists, as
// well as the most recent timestamps for each policy (if they exists).
type edgeCache struct {
	n     int
	edges map[uint64]edgeCacheEntry
}

// newEdgeCache creates a new edgeCache with maximum capacity of n entries.
func newEdgeCache(n int) *edgeCache {
	return &edgeCache{
		n:     n,
		edges: make(map[uint64]edgeCacheEntry),
	}
}

// get returns the entry from the cache for chanid, if it exists.
func (c *edgeCache) get(chanid uint64) (edgeCacheEntry, bool) {
	entry, ok := c.edges[chanid]
	return entry, ok
}

// insert adds the entry to the edge cache. If an entry for chanid already
// exists, it will be replaced with the new entry. If the entry doesn't exists,
// it will be inserted to the cache, performing a random eviction if the cache
// is at capacity.
func (c *edgeCache) insert(chanid uint64, entry edgeCacheEntry) {
	// If entry exists, replace it.
	if _, ok := c.edges[chanid]; ok {
		c.edges[chanid] = entry
		return
	}

	// Otherwise, evict an entry at random and insert.
	if len(c.edges) == c.n {
		for id := range c.edges {
			delete(c.edges, id)
			break
		}
	}
	c.edges[chanid] = entry
}

// remove deletes an entry for chanid from the cache, if it exists.
func (c *edgeCache) remove(chanid uint64) {
	delete(c.edges, chanid)
}

// channelCache is an in-memory cache used to improve the performance of
// ChanUpdatesInHorizon. It caches the chan info and edge policies for a
// particular channel.
type channelCache struct {
	n        int
	channels map[uint64]ChannelEdge
}

// newChannelCache creates a new channelCache with maximum capacity of n
// channels.
func newChannelCache(n int) *channelCache {
	return &channelCache{
		n:        n,
		channels: make(map[uint64]ChannelEdge),
	}
}

// get returns the channel from the cache, if it exists.
func (c *channelCache) get(chanid uint64) (ChannelEdge, bool) {
	channel, ok := c.channels[chanid]
	return channel, ok
}

// insert adds the entry to the channel cache. If an entry for chanid already
// exists, it will be replaced with the new entry. If the entry doesn't exist,
// it will be inserted to the cache, performing a random eviction if the cache
// is at capacity.
func (c *channelCache) insert(chanid uint64, channel ChannelEdge) {
	// If entry exists, replace it.
	if _, ok := c.channels[chanid]; ok {
		c.channels[chanid] = channel
		return
	}

	// Otherwise, evict an entry at random and insert.
	if len(c.channels) == c.n {
		for id := range c.channels {
			delete(c.channels, id)
			break
		}
	}
	c.channels[chanid] = channel
}

// remove deletes an edge for chanid from the cache, if it exists.
func (c *channelCache) remove(chanid uint64) {
	delete(c.channels, chanid)
}
