package wtwire

import (
	"io"
)

// Ack is sent from tower to client as reponse to WatchInfo and
// StateUpdate messages.
type Ack struct {
	LastApplied uint16
}

// A compile time check to ensure Ack implements the wtwire.Message
// interface.
var _ Message = (*Ack)(nil)

// Decode deserializes a serialized Ack message stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (t *Ack) Decode(r io.Reader, pver uint32) error {
	return readElements(r,
		&t.LastApplied,
	)
}

// Encode serializes the target Ack into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the wtwire.Message interface.
func (t *Ack) Encode(w io.Writer, pver uint32) error {
	return writeElements(w,
		t.LastApplied,
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the wtwire.Message interface.
func (t *Ack) MsgType() MessageType {
	return MsgAck
}

// MaxPayloadLength returns the maximum allowed payload size for a Ack
// complete message observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (t *Ack) MaxPayloadLength(uint32) uint32 {
	return 2
}
