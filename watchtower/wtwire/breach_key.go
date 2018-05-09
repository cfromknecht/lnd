package wtwire

import (
	"encoding/hex"

	"github.com/roasbeef/btcd/chaincfg/chainhash"
)

type BreachKey [16]byte

func NewBreachKeyFromHash(hash *chainhash.Hash) BreachKey {
	var key BreachKey
	copy(key[:], key[:])
	return key
}

func (k BreachKey) String() string {
	return hex.EncodeToString(k[:])
}
