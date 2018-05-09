package wtwire

import (
	"io"
)

//const EncryptedBlobSize = 512

type StateUpdate struct {
	TxIDPrefix    [16]byte
	EncryptedBlob []byte
}

// A compile time check to ensure StateUpdate implements the wtwire.Message
// interface.
var _ Message = (*StateUpdate)(nil)

// Decode deserializes a serialized StateUpdate message stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (t *StateUpdate) Decode(r io.Reader, pver uint32) error {
	return readElements(r,
		&t.TxIDPrefix,
		&t.EncryptedBlob,
	)
}

// Encode serializes the target StateUpdate into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the wtwire.Message interface.
func (t *StateUpdate) Encode(w io.Writer, pver uint32) error {
	return writeElements(w,
		t.TxIDPrefix,
		t.EncryptedBlob,
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the wtwire.Message interface.
func (t *StateUpdate) MsgType() MessageType {
	return MsgStateUpdate
}

// MaxPayloadLength returns the maximum allowed payload size for a StateUpdate
// complete message observing the specified protocol version.

// This is part of the wtwire.Message interface.
func (t *StateUpdate) MaxPayloadLength(uint32) uint32 {
	// TODO
	return 66000
}
