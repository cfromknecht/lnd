package wtwire

import (
	"io"
)

// WatchResponse is sent from tower to client as reponse to a WatchRequest.
type WatchResponse struct {
	SessionID    uint64
	Accept       uint8
	OutputScript [20]byte
}

// A compile time check to ensure WatchResponse implements the wtwire.Message
// interface.
var _ Message = (*WatchResponse)(nil)

// Decode deserializes a serialized WatchResponse message stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (t *WatchResponse) Decode(r io.Reader, pver uint32) error {
	return readElements(r, &t.SessionID, &t.Accept, t.OutputScript[:])
}

// Encode serializes the target WatchResponse into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the wtwire.Message interface.
func (t *WatchResponse) Encode(w io.Writer, pver uint32) error {
	return writeElements(w, t.SessionID, t.Accept, t.OutputScript[:])
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the wtwire.Message interface.
func (t *WatchResponse) MsgType() MessageType {
	return MsgWatchResponse
}

// MaxPayloadLength returns the maximum allowed payload size for a WatchResponse
// complete message observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (t *WatchResponse) MaxPayloadLength(uint32) uint32 {
	// TODO
	return 1024
}
