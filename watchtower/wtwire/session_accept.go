package wtwire

type SessionAccept struct {
	RewardPkScript []byte
	// TODO(conner): respond with payment request
}

// A compile time check to ensure SessionAccept implements the wtwire.Message
// interface.
var _ Message = (*SessionAccept)(nil)

// Decode deserializes a serialized SessionAccept message stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (m *SessionAccept) Decode(r io.Reader, pver uint32) error {
	return readElements(r,
		&m.RewardPkScript,
	)
}

// Encode serializes the target SessionAccept into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the wtwire.Message interface.
func (m *SessionAccept) Encode(w io.Writer, pver uint32) error {
	return writeElements(w,
		m.RewardPkScript,
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the wtwire.Message interface.
func (m *SessionAccept) MsgType() MessageType {
	return MsgSessionAccept
}

// MaxPayloadLength returns the maximum allowed payload size for a SessionAccept
// complete message observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (m *SessionAccept) MaxPayloadLength(uint32) uint32 {
	// TODO
	return 1024
}
