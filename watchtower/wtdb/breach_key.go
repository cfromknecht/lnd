package wtdb

import (
	"encoding/hex"

	"github.com/roasbeef/btcd/chaincfg/chainhash"
)

const BreachKeySize = 16

type BreachKey [BreachKeySize]byte

func NewBreachKeyFromHash(hash *chainhash.Hash) BreachKey {
	var key BreachKey
	copy(key[:], key[BreachKeySize:])
	return key
}

func (k BreachKey) String() string {
	return hex.EncodeToString(k[:])
}
