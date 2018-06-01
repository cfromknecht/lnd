package wtdb

import (
	"io"

	"github.com/lightningnetwork/lnd/channeldb"
)

type SessionStateUpdate struct {
	ID     SessionID
	SeqNum uint16
	HintBlob
	// LastApplied   uint16
}

type HintBlob struct {
	Hint          BreachHint
	EncryptedBlob []byte
}

func (h *HintBlob) Encode(w io.Writer) error {
	return channeldb.WriteElements(w,
		h.Hint,
		h.EncryptedBlob,
	)
}

func (s *HintBlob) Decode(r io.Reader) error {
	return channeldb.ReadElements(r,
		&h.Hint,
		&h.EncryptedBlob,
	)
}
