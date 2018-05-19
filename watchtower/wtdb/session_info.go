package wtdb

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/lightningnetwork/lnd/lnwallet"
)

var (
	ErrUpdateOutOfOrder     = errors.New("update sequence number is not sequential")
	ErrLastAppliedReversion = errors.New("update last applied must be non-decreasing")
	ErrSeqNumAlreadyApplied = errors.New("update sequence number has already been applied")
	ErrSessionExpired       = errors.New("all session updates have been consumed")
)

type SessionInfo struct {
	ID SessionID

	Version uint16

	MaxUpdates  uint16
	LastSeqNum  uint16
	LastApplied uint16

	RewardRate   uint32
	SweepFeeRate lnwallet.SatPerVByte

	RewardAddress []byte
	SweepAddress  []byte
}

func (s *SessionInfo) ComputeSweepOutputs(totalAmt int64,
	vSize int64) (int64, int64, error) {

	rewardAmt := (totalAmt*int64(s.RewardRate) + 999) / 1000
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

	s.LastSeqNum = seqNum
	s.LastApplied = lastApplied

	return nil
}

func (s *SessionInfo) Encode(w io.Writer) error {
	if err := binary.Write(w, byteOrder, s.Version); err != nil {
		return err
	}
	if err := binary.Write(w, byteOrder, s.MaxUpdates); err != nil {
		return err
	}
	if err := binary.Write(w, byteOrder, s.LastSeqNum); err != nil {
		return err
	}
	if err := binary.Write(w, byteOrder, s.LastApplied); err != nil {
		return err
	}
	if err := binary.Write(w, byteOrder, s.RewardRate); err != nil {
		return err
	}
	if err := binary.Write(w, byteOrder, s.SweepFeeRate); err != nil {
		return err
	}
	if _, err := w.Write(s.RewardAddress); err != nil {
		return err
	}

	_, err := w.Write(s.SweepAddress)
	return err
}

func (s *SessionInfo) Decode(r io.Reader) error {
	if err := binary.Read(r, byteOrder, &s.Version); err != nil {
		return err
	}
	if err := binary.Read(r, byteOrder, &s.MaxUpdates); err != nil {
		return err
	}
	if err := binary.Read(r, byteOrder, &s.LastSeqNum); err != nil {
		return err
	}
	if err := binary.Read(r, byteOrder, &s.LastApplied); err != nil {
		return err
	}
	if err := binary.Read(r, byteOrder, &s.RewardRate); err != nil {
		return err
	}
	if err := binary.Read(r, byteOrder, &s.SweepFeeRate); err != nil {
		return err
	}

	s.RewardAddress = make([]byte, 64)
	if _, err := r.Read(s.RewardAddress); err != nil {
		return err
	}

	s.SweepAddress = make([]byte, 64)
	_, err := r.Read(s.SweepAddress)
	return err
}
