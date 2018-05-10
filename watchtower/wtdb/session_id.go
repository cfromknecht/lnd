package wtdb

import (
	"encoding/hex"

	"github.com/roasbeef/btcd/btcec"
)

const SessionIDSize = 33

type SessionID [SessionIDSize]byte

func NewSessionIDFromPubKey(pubKey *btcec.PublicKey) SessionID {
	var sid SessionID
	copy(sid[:], pubKey.SerializeCompressed())
	return sid
}

func (s SessionID) String() string {
	return hex.EncodeToString(s[:])
}
