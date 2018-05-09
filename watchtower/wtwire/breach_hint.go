package wtwire

import (
	"encoding/hex"

	"github.com/roasbeef/btcd/chaincfg/chainhash"
)

type BreachHint [16]byte

func NewBreachHintFromHash(hash *chainhash.Hash) BreachHint {
	var hint BreachHint
	copy(hint[:], hash[:16])
	return hint
}

func (h BreachHint) String() string {
	return hex.EncodeToString(h[:])
}
