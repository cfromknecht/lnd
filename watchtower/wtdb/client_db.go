package wtdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/coreos/bbolt"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
)

const clientDbName = "wt_client.db"

var (
	backupBucket = []byte("backups")

	sessionBucket = []byte("sessions")

	ErrCorruptClientDB = errors.New("watchtower client db is corrupted")

	ErrChannelNotFound = errors.New("channel backups not found")

	ErrRevokedStateNotFound = errors.New("unable to find revoked state")
	ErrBackupAlreadyExists  = errors.New("backup for state already exists")
)

type BackupState byte

const (
	BackupStateCommitted BackupState = 0
	BackupStateInFlight              = 1
	BackupStateCompleted             = 2
)

type RevokedState struct {
	ChanID       lnwire.ChannelID
	CommitHeight uint64
	CommitTxID   chainhash.Hash
	CommitTx     *wire.MsgTx
	State        BackupState
}

func (s *RevokedState) Encode(w io.Writer) error {
	if _, err := w.Write(s.ChanID[:]); err != nil {
		return err
	}
	if err := binary.Write(w, byteOrder, s.CommitHeight); err != nil {
		return err
	}
	if _, err := w.Write(s.CommitTxID[:]); err != nil {
		return err
	}
	err := binary.Write(w, byteOrder, s.State)
	return err
}

func (s RevokedState) Decode(r io.Reader) error {
	if _, err := r.Read(s.ChanID[:]); err != nil {
		return err
	}
	if err := binary.Read(r, byteOrder, &s.CommitHeight); err != nil {
		return err
	}
	if _, err := r.Read(s.CommitTxID[:]); err != nil {
		return err
	}
	err := binary.Read(r, byteOrder, &s.State)
	return err
}

type ClientDB struct {
	*bolt.DB
	dbPath string
}

func OpenClientDB(dbPath string) (*ClientDB, error) {
	bdb, err := createDB(dbPath, clientDbName)
	if err != nil {
		return nil, err
	}

	db := &ClientDB{
		DB:     bdb,
		dbPath: dbPath,
	}

	err = db.initBuckets()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (d *ClientDB) initBuckets() error {
	return d.DB.Update(func(tx *bolt.Tx) error {
		var err error
		_, err = tx.CreateBucketIfNotExists(backupBucket)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(sessionBucket)
		return err
	})
}

func (d *ClientDB) BeginStateBackup(state *RevokedState) error {
	return d.DB.Update(func(tx *bolt.Tx) error {
		backups := tx.Bucket(backupBucket)
		if backups == nil {
			return ErrCorruptClientDB
		}

		_, err := getRevokedState(
			backups, state.ChanID, state.CommitHeight,
		)
		switch {
		case err == nil:
			return ErrBackupAlreadyExists
		case err == ErrRevokedStateNotFound:
			// First time adding backup, proceed.
		case err != nil:
			return err
		}

		// Ensure the first state we record is BackupStateCommitted.
		state.State = BackupStateCommitted

		return putRevokedState(backups, state)
	})
}

func (d *ClientDB) ReportBackupFailed(state *RevokedState) error {
	return d.DB.Update(func(tx *bolt.Tx) error {
		backups := tx.Bucket(backupBucket)
		if backupBucket == nil {
			return ErrCorruptClientDB
		}

		currState, err := getRevokedState(
			backups, state.ChanID, state.CommitHeight,
		)
		if err != nil {
			return err
		}

		// TODO(conner) Validate state transition
		currState.State = BackupStateCommitted
		state.State = BackupStateCommitted

		return putRevokedState(currState)
	})
}

func (d *ClientDB) ReportBackupSuccess(state *RevokedState) error {
	return d.DB.Update(func(tx *bolt.Tx) error {
		backups := tx.Bucket(backupBucket)
		if backupBucket == nil {
			return ErrCorruptClientDB
		}

		currState, err := getRevokedState(
			backups, state.ChanID, state.CommitHeight,
		)
		if err != nil {
			return err
		}

		// TODO(conner) Validate state transition
		currState.State = BackupStateCompleted
		state.State = BackupStateCompleted

		return putRevokedState(currState)
	})
}

func (d *ClientDB) AckBackup(state *RevokedState) error {
	return d.DB.Update(func(tx *bolt.Tx) error {
		backups := tx.Bucket(backupBucket)
		if backups == nil {
			return ErrCorruptClientDB
		}

		return removeRevokedState(state)
	})
}

func (d *ClientDB) ListBackups() ([]*RevokedState, error) {
	var revokedStates []*RevokedState
	err := d.DB.View(func(tx *bolt.Tx) error {
		backups := tx.Bucket(backupBucket)
		if backups == nil {
			return ErrCorruptClientDB
		}

		var err error
		revokedStates, err = listBackups(backups)
		return err
	})
	if err != nil {
		return err
	}

	return revokedStates, nil
}

func listBackups(backups *bolt.Bucket) ([]*RevokedState, error) {
	var revokedStates []*RevokedState
	err := backups.ForEach(func(chanID, _ []byte) error {
		chanBucket := backups.Bucket(chanID)
		if chanBucket == nil {
			return ErrCorruptClientDB
		}

		return chanBucket.ForEach(func(_, v []byte) error {
			state := &RevokedState{}
			err := state.Decode(bytes.NewReader(v))
			if err != nil {
				return err
			}

			revokedStates = append(revokedStates, state)

			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	return revokedStates, nil
}

func (d *ClientDB) Wipe() error {
	return d.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket(backupBucket)
		if err != nil && err != bolt.ErrBucketNotFound {
			return err
		}
		err = tx.DeleteBucket(sessionBucket)
		if err != nil && err != bolt.ErrBucketNotFound {
			return err
		}
		return nil
	})
}

func putRevokedState(backups *bolt.Bucket, state *RevokedState) error {
	chanBucket, err := backups.CreateBucketIfNotExists(state.ChanID[:])
	if err != nil {
		return err
	}

	var b bytes.Buffer
	if err := state.Encode(&b); err != nil {
		return err
	}

	var commitHeightKey [8]byte
	byteOrder.PutUint64(commitHeightKey[:], state.CommitHeight)

	return heightBucket.Put(commitHeightKey[:], b.Bytes())
}

func getRevokedState(backups *bolt.Bucket, chanID lnwire.ChannelID,
	commitHeight uint64) (*RevokedState, error) {

	chanBucket := backups.Bucket(chanID[:])
	if chanBucket == nil {
		return ErrRevokedStateNotFound
	}

	var commitHeightKey [8]byte
	byteOrder.PutUint64(commitHeightKey[:], commitHeight)

	revokedStateBytes := chanBucket.Get(commitHeightKey[:])
	if revokedStateBytes == nil {
		return ErrRevokedStateNotFound
	}

	revokedState := &RevokedState{}
	err := revokedState.Decode(bytes.NewReader(revokedStateBytes))
	if err != nil {
		return err
	}

	return revokedState, nil
}

func removeRevokedState(backups *bolt.Bucket, state *RevokedState) error {
	chanBucket := backups.Bucket(state.ChanID[:])
	if chanBucket == nil {
		return ErrRevokedStateNotFound
	}

	var commitHeightKey [8]byte
	byteOrder.PutUint64(commitHeightKey[:], state.CommitHeight)

	err := chanBucket.Delete(commitHeightKey[:])
	if err != nil {
		return err
	}

	err = isBucketEmpty(chanBucket)
	switch {
	case err == errBucketNotEmpty:
		return nil
	case err != nil:
		return err
	}

	return backups.Delete(state.ChanID[:])
}