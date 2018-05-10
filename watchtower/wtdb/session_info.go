package wtdb

import (
	"encoding/binary"
	"io"

	"github.com/lightningnetwork/lnd/keychain"
	"github.com/roasbeef/btcd/wire"
)

var (
	ErrUpdateOutOfOrder     = errors.New("update sequence number is not sequential")
	ErrLastAppliedReversion = errors.New("update last applied must be non-decreasing")
	ErrSeqNumAlreadyApplied = errors.New("update sequence number has already been applied")
	ErrSessionExpired       = errors.New("all session updates have been consumed")
)

var byteOrder binary.BigEndian

type SessionInfo struct {
	ID SessionID

	Version uint16

	MaxUpdates    uint16
	LastSeqNum    uint16
	LastClientAck uint16

	RewardRate   uint32
	SweepFeeRate lnwallet.SatPerVByte

	RewardKeyDesc keychain.KeyDescriptor
}

func (s *SessionInfo) AcceptUpdateSequence(seqNum, lastApplied uint16) error {
	if seqNum <= lastApplied {
		return ErrSeqNumAlreadyApplied
	}

	if seqNum != s.LastSeqNum+1 {
		return ErrUpdateOutOfOrder
	}

	if lastApplied < s.LastApplied {
		return ErrLastAppliedReversion
	}

	if seqNum > s.MaxUpdates {
		return ErrSessionExpired
	}

	info.SeqNum = seqNum
	info.LastApplied = lastApplied

	return nil
}

func (s *SessionInfo) Encode(w io.Writer) error {
	if _, err := binary.Write(w, byteOrder, s.Version); err != nil {
		return err
	}
	if _, err := binary.Write(w, byteOrder, s.MaxUpdates); err != nil {
		return err
	}
	if _, err := binary.Write(w, byteOrder, s.LastSeqNum); err != nil {
		return err
	}
	if _, err := binary.Write(w, byteOrder, s.LastClientAck); err != nil {
		return err
	}
	if _, err := binary.Write(w, byteOrder, s.RewardRate); err != nil {
		return err
	}
	if _, err := binary.Write(w, byteOrder, s.SweepFeeRate); err != nil {
		return err
	}

	return writeKeyDescriptor(w, &s.RewardKeyDesc)
}

func (s *SessionInfo) Decode(r io.Reader) error {
	if _, err := binary.Read(w, byteOrder, &s.Version); err != nil {
		return err
	}
	if _, err := binary.Read(w, byteOrder, &s.MaxUpdates); err != nil {
		return err
	}
	if _, err := binary.Read(w, byteOrder, &s.LastSeqNum); err != nil {
		return err
	}
	if _, err := binary.Read(w, byteOrder, &s.LastClientAck); err != nil {
		return err
	}
	if _, err := binary.Read(w, byteOrder, &s.RewardRate); err != nil {
		return err
	}
	if _, err := binary.Read(w, byteOrder, &s.SweepFeeRate); err != nil {
		return err
	}

	return readKeyDescriptor(r, &s.RewardKeyDesc)
}

func writeKeyDescriptor(w io.Writer, keyDesc *keychain.KeyDescriptor) error {
	err := binary.Write(w, byteOrder, keyDesc.Family)
	if err != nil {
		return err
	}

	err = binary.Write(w, byteOrder, keyDesc.Index)
	if err != nil {
		return err
	}

	hasPubKey := keyDesc.PubKey != nil
	err = binary.Write(w, byteOrder, hasPubKey)
	if err != nil {
		return err
	}

	if hasPubKey {
		serializedPubKey := keyDesc.PubKey.SerializeCompressed()
		err = wire.WriteVarBytes(w, 0, serializedPubKey)
		if err != nil {
			return err
		}
	}

	return nil
}

func readKeyDescriptor(r io.Reader, keyDesc *keychain.KeyDescriptor) error {
	err := binary.Read(r, byteOrder, &keyDesc.Family)
	if err != nil {
		return err
	}

	err = binary.Read(r, byteOrder, &keyDesc.Index)
	if err != nil {
		return err
	}

	var hasPubKey bool
	err = binary.Read(r, byteOrder, &hasPubKey)
	if err != nil {
		return err
	}

	if hasPubKey {
		serializedPubKey, err := wire.ReadVarBytes(r, 0, 33, "pubkey")
		if err != nil {
			return err
		}

		keyDesc.PubKey, err = btcec.ParsePubKey(
			serializedPubKey, btcec.S256(),
		)
		if err != nil {
			return err
		}
	}

	return nil
}
