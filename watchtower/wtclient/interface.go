package wtclient

import (
	"net"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/lightningnetwork/lnd/watchtower/wtserver"
	"github.com/lightningnetwork/lnd/watchtower/wtwire"
)

type DB interface {
	CreateTower(*lnwire.NetAddress) (*wtdb.Tower, error)

	GetChanBackupHeight(chanID lnwire.ChannelID) (uint64, error)

	SetChanBackupHeight(chanID lnwire.ChannelID,
		commitHeight uint64, towerID uint32) error

	CommitStateUpdate(*wtdb.SessionID, *wtwire.StateUpdate) error

	ListActiveSessions() ([]*wtdb.ClientSessionInfo, error)

	CreateClientSession(*wtdb.ClientSessionInfo) error
}

// NetDialer connects to a remote node using an authenticated transport, such as
// brontide. The dialer argument is used to specify a resolver, which allows
// this method to be used over Tor or clear net connections.
type NetDialer func(localPriv *btcec.PrivateKey, netAddr *lnwire.NetAddress,
	dialer func(string, string) (net.Conn, error)) (wtserver.Peer, error)

// NetDial is the watchtower client's default method of dialing.
func NetDial(localPriv *btcec.PrivateKey, netAddr *lnwire.NetAddress,
	dialer func(string, string) (net.Conn, error)) (wtserver.Peer, error) {

	return brontide.Dial(localPriv, netAddr, dialer)
}
