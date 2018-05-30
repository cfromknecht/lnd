package wtdb

import (
	"io"

	"github.com/lightningnetwork/lnd/lnwire"
)

var towerBucket = []byte("towers")

type Tower struct {
	ID   uint64
	Addr *lnwire.NetAddress
}

func (t *Tower) Encode(w io.Writer) error {
	return nil
}
