package wtdb

type SessionStateUpdate struct {
	ID            SessionID
	Hint          BreachHint
	SeqNum        uint16
	LastApplied   uint16
	EncryptedBlob []byte
}
