package wtdb

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/watchtower/wtwire"
)

// ClientSessionInfo encapsulates a SessionInfo returned from a successful
// session negotiation, and also records the tower and ephemeral secret used for
// communicating with the tower.
type ClientSessionInfo struct {
	// SessionInfo holds the session parameters defining how to construct
	// the justice transaction.
	SessionInfo

	// TowerID is the unique, db-assigned identifier that references the
	// Tower with which the session is negotiated.
	TowerID uint32

	// Tower holds the pubkey and address of the watchtower.
	//
	// NOTE: This value is not serialized. It is recovered by looking up the
	// tower with TowerID.
	Tower *Tower

	// SessionPrivKey is the ephemeral secret key used to connect to the
	// watchtower.
	SessionPrivKey *btcec.PrivateKey

	SessionKeyDesc keychain.KeyLocator

	LocalInit *wtwire.Init
}
