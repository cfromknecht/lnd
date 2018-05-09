package wtwire

import (
	"io"
)

// WatchRequest is sent from a client to tower when he wants to open
// a watch session for a particular channel.
type WatchRequest struct {
	// NOTE: assign random id, rename to SessionID
	SessionID    uint64
	OutputReward uint64
}

// A compile time check to ensure WatchRequest implements the wtwire.Message
// interface.
var _ Message = (*WatchRequest)(nil)

// Decode deserializes a serialized WatchRequest message stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (t *WatchRequest) Decode(r io.Reader, pver uint32) error {
	return readElements(r, &t.SessionID, &t.OutputReward)
}

// Encode serializes the target WatchRequest into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the wtwire.Message interface.
func (t *WatchRequest) Encode(w io.Writer, pver uint32) error {
	return writeElements(w, t.SessionID, t.OutputReward)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the wtwire.Message interface.
func (t *WatchRequest) MsgType() MessageType {
	return MsgWatchRequest
}

// MaxPayloadLength returns the maximum allowed payload size for a WatchRequest
// complete message observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (t *WatchRequest) MaxPayloadLength(uint32) uint32 {
	// TODO
	return 1024
}
