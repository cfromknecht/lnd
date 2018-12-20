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

// DB abstracts the required database operations required by the watchtower
// client.
type DB interface {
	// CreateTower initialize an address record used to communicate with a
	// watchtower. Each Tower is assigned a unique ID, that is used to
	// amortize storage costs of the public key when used by multiple
	// sessions.
	CreateTower(*lnwire.NetAddress) (*wtdb.Tower, error)

	GetChanBackupHeight(chanID lnwire.ChannelID) (uint64, error)

	SetChanBackupHeight(chanID lnwire.ChannelID,
		commitHeight uint64, towerID uint32) error

	GetLastCommitHeight(chanID lnwire.ChannelID) (uint64, error)

	MarkBackupIneligible(chanID lnwire.ChannelID, commitHeight uint64) error

	// CommitBackup writes the next state update for a particular
	// session, so that we can be sure to resend it after a restart if it
	// hasn't been ACK'd by the tower. The sequence number of the update
	// should be exactly one greater than the existing entry, and less that
	// or equal to the session's MaxUpdates.
	CommitBackup(chanID lnwire.ChannelID, commitHeight uint64,
		sessionID *wtdb.SessionID, stateUpdate *wtwire.StateUpdate) error

	// CreateClientSession
	CreateClientSession(*wtdb.ClientSessionInfo) error

	// ListActiveSessions returns all sessions that have not yet been
	// exhausted. This is used on startup to find any sessions which may
	// still be able to accept state updates.
	ListActiveSessions() (map[wtdb.SessionID]*wtdb.ClientSessionInfo, error)
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
