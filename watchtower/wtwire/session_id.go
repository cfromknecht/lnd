package wtwire

import "encoding/hex"

type SessionID [33]byte

func NewSessionIDFromPubKey(pubKey *btcec.PublicKey) SessionID {
	var sid SessionID
	copy(sid[:], pk.SerializeCompressed())
	return sid
}

func (s SessionID) String() string {
	return hex.EncodeToString(s[:])
}
