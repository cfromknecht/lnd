package wtdb

// ClientStateUpdate holds a state update sent by a client along with its
// SessionID.
type ClientStateUpdate struct {
	// ID the session id of the client who sent the state update.
	ID SessionID

	// Hint is the 16-byte prefix of the revoked commitment transaction.
	Hint BreachHint

	// EncryptedBlob is a ciphertext containing the sweep information for
	// exacting justice if the commitment transaction matching the breach
	// hint is braodcast.
	EncryptedBlob []byte
}
