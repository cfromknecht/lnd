package wtwire

import (
	"encoding/hex"

	"github.com/roasbeef/btcd/btcec"
)

type SessionID [33]byte

func NewSessionIDFromPubKey(pubKey *btcec.PublicKey) SessionID {
	var sid SessionID
	copy(sid[:], pubKey.SerializeCompressed())
	return sid
}

func (s SessionID) String() string {
	return hex.EncodeToString(s[:])
}
