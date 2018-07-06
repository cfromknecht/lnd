package wtwire

import (
	"io"

	"github.com/lightningnetwork/lnd/lnwallet"
)

// SessionInit is sent from a client to tower when he wants to open
// a watch session for a particular channel.
type SessionInit struct {
	Version      uint16
	MaxUpdates   uint16
	RewardRate   uint32
	SweepFeeRate lnwallet.SatPerVByte
}

// A compile time check to ensure SessionInit implements the wtwire.Message
// interface.
var _ Message = (*SessionInit)(nil)

// Decode deserializes a serialized SessionInit message stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (m *SessionInit) Decode(r io.Reader, pver uint32) error {
	return readElements(r,
		&m.Version,
		&m.MaxUpdates,
		&m.RewardRate,
		&m.SweepFeeRate,
	)
}

// Encode serializes the target SessionInit into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the wtwire.Message interface.
func (m *SessionInit) Encode(w io.Writer, pver uint32) error {
	return writeElements(w,
		m.Version,
		m.MaxUpdates,
		m.RewardRate,
		m.SweepFeeRate,
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the wtwire.Message interface.
func (m *SessionInit) MsgType() MessageType {
	return MsgSessionInit
}

// MaxPayloadLength returns the maximum allowed payload size for a SessionInit
// complete message observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (m *SessionInit) MaxPayloadLength(uint32) uint32 {
	// TODO
	return 1024
}
