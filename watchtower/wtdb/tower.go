package wtdb

import (
	"net"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/lnwire"
)

// Tower holds the necessary components required to connect to a remote tower.
// Communication is handled by brontide, and requires both a public key and an
// address.
type Tower struct {
	// ID is a unique ID for this record assigned by the database.
	ID uint64

	// IdentityKey is the public key of the remote node, used to
	// authenticate the brontide transport.
	IdentityKey *btcec.PublicKey

	// Addresses is a list of possible addresses to reach the tower.
	Addresses []net.Addr
}

func (t *Tower) AddAddress(addr net.Addr) {
	// Ensure we don't add a duplicate address.
	addrStr := addr.String()
	for _, existingAddr := range t.Addresses {
		if existingAddr.String() == addrStr {
			return
		}
	}

	// Add this address to the front of the list, on the assumption that it
	// is a fresher address and will be tried first.
	t.Addresses = append([]net.Addr{addr}, t.Addresses...)
}

// ToLNAddrs generates a list of lnwire.NetAddress from a Tower instance. This
// can be used to have a client try multiple addresses for the same tower.
func (t *Tower) ToLNAddrs() []*lnwire.NetAddress {
	lnAddrs := make([]*lnwire.NetAddress, 0, len(t.Addresses))
	for _, addr := range t.Addresses {
		lnAddrs = append(lnAddrs, &lnwire.NetAddress{
			IdentityKey: t.IdentityKey,
			Address:     addr,
		})
	}

	return lnAddrs
}