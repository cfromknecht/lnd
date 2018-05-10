package wtdb

import (
	"encoding/hex"

	"github.com/roasbeef/btcd/chaincfg/chainhash"
)

const BreachHintSize = 16

type BreachHint [BreachHintSize]byte

func NewBreachHintFromHash(hash *chainhash.Hash) BreachHint {
	var hint BreachHint
	copy(hint[:], hash[:BreachHintSize])
	return hint
}

func (h BreachHint) String() string {
	return hex.EncodeToString(h[:])
}
