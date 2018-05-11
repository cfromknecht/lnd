package wtwire

/*
import "io"

// SessionInfo is sent from a client to tower when he wants to open
// a watch session for a particular channel.
type SessionInfo struct {
	// NOTE: assign random id, rename to SessionID
	SessionID uint64
	//RevocationBasePoint   *btcec.PublicKey
	//LocalDelayedBasePoint *btcec.PublicKey
	CsvDelay          uint16
	OutputScript      []byte
	OutputReward      uint64
	TowerOutputScript []byte
	FeeRate           uint64
}

// A compile time check to ensure SessionInfo implements the wtwire.Message
// interface.
var _ Message = (*SessionInfo)(nil)

// Decode deserializes a serialized SessionInfo message stored in the passed
// io.Reader observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (t *SessionInfo) Decode(r io.Reader, pver uint32) error {
	return readElements(r,
		&t.SessionID,
		//&t.RevocationBasePoint,
		//&t.LocalDelayedBasePoint,
		&t.CsvDelay,
		&t.OutputScript,
		&t.OutputReward,
		&t.TowerOutputScript,
		&t.FeeRate,
	)
}

// Encode serializes the target SessionInfo into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the wtwire.Message interface.
func (t *SessionInfo) Encode(w io.Writer, pver uint32) error {
	return writeElements(w,
		t.SessionID,
		//t.RevocationBasePoint,
		//t.LocalDelayedBasePoint,
		t.CsvDelay,
		t.OutputScript,
		t.OutputReward,
		t.TowerOutputScript,
		t.FeeRate,
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the wtwire.Message interface.
func (t *SessionInfo) MsgType() MessageType {
	return MsgSessionInfo
}

// MaxPayloadLength returns the maximum allowed payload size for a SessionInfo
// complete message observing the specified protocol version.
//
// This is part of the wtwire.Message interface.
func (t *SessionInfo) MaxPayloadLength(uint32) uint32 {
	// TtODO
	return 1024
}
*/
