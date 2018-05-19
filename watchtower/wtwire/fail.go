package wtwire

import "io"

// Fail is sent from tower to client as reponse to WatchInfo and
// StateUpdate messages.
type Fail struct {
	Code uint16
}

// A compile time check to ensure Fail implements the wtwire.Message
// interface.
var _ Message = (*Fail)(nil)

// Decode deserializes a serialized Fail message stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (t *Fail) Decode(r io.Reader, pver uint32) error {
	return readElements(r,
		&t.Code,
	)
}

// Encode serializes the target Fail into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the wtwire.Message interface.
func (t *Fail) Encode(w io.Writer, pver uint32) error {
	return writeElements(w,
		t.Code,
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the wtwire.Message interface.
func (t *Fail) MsgType() MessageType {
	return MsgFail
}

// MaxPayloadLength returns the maximum allowed payload size for a Fail
// complete message observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (t *Fail) MaxPayloadLength(uint32) uint32 {
	return 2
}
