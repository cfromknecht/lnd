package lncfg

import (
	"fmt"

	"github.com/lightningnetwork/lnd/discovery"
	"github.com/lightningnetwork/lnd/routing/route"
)

type Gossip struct {
	PinnedSyncersRaw []string `long:"pinned-syncers" description:"A set of peers that should always remain in an active sync state, which can be used to closely synchronize the routing tables of two nodes. The value should be comma separated list of hex-encoded pubkeys. Connected peers matching this pubkey will remain active for the duration of the connection and not count towards the NumActiveSyncer count."`

	PinnedSyncers discovery.PinnedSyncers
}

func (g *Gossip) Parse() error {
	pinnedSyncers := make(discovery.PinnedSyncers)
	for _, pubkeyStr := range g.PinnedSyncersRaw {
		vertex, err := route.NewVertexFromStr(pubkeyStr)
		if err != nil {
			return err
		}
		fmt.Printf("vertex: %v\n", vertex)
		pinnedSyncers[vertex] = struct{}{}
	}

	g.PinnedSyncers = pinnedSyncers

	return nil
}
