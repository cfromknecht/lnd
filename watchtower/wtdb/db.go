package wtdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/coreos/bbolt"
)

const serverDbName = "wt_server.db"

var (
	hintBucket    = []byte("hints")
	sessionBucket = []byte("sessions")

	// Big endian is the preferred byte order, due to cursor scans over
	// integer keys iterating in order.
	byteOrder = binary.BigEndian

	ErrCorruptTxnDB = errors.New("transaction db is corrupted")

	ErrSessionNotFound = errors.New("session not found in db")

	ErrSessionAlreadyExists = errors.New("session already exists")
)

type DB struct {
	*bolt.DB
	dbPath string
}

func Open(dbPath string) (*DB, error) {
	bdb, err := createDB(dbPath, serverDbName)
	if err != nil {
		return nil, err
	}

	db := &DB{
		DB:     bdb,
		dbPath: dbPath,
	}

	return db, db.initBuckets()
}

func (d *DB) initBuckets() error {
	return d.DB.Update(func(tx *bolt.Tx) error {
		var err error
		_, err = tx.CreateBucketIfNotExists(hintBucket)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(sessionBucket)
		return err
	})
}

func (d *DB) InsertSessionInfo(info *SessionInfo) error {
	return d.DB.Batch(func(tx *bolt.Tx) error {
		return putSessionInfo(tx, info, true)
	})
}

func (d *DB) GetSessionInfo(sessionID *SessionID) (*SessionInfo, error) {
	var info *SessionInfo
	err := d.View(func(tx *bolt.Tx) error {
		var err error
		info, err = getSessionInfo(tx, sessionID)
		return err
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

func (d *DB) InsertStateUpdate(update *SessionStateUpdate) error {
	return d.Batch(func(tx *bolt.Tx) error {
		info, err := getSessionInfo(tx, &update.ID)
		if err != nil {
			return err
		}

		err = info.AcceptUpdateSequence(
			update.SeqNum, update.LastApplied,
		)
		if err != nil {
			return err
		}

		err = putSessionInfo(tx, info, false)
		if err != nil {
			return err
		}

		hints := tx.Bucket(hintBucket)
		if hints == nil {
			return ErrCorruptTxnDB
		}

		hintSessions, err := hints.CreateBucketIfNotExists(
			update.Hint[:],
		)
		if err != nil {
			return err
		}

		fmt.Printf("storing blob: %s\n", string(update.EncryptedBlob))

		return hintSessions.Put(update.ID[:], update.EncryptedBlob)
	})
}

type Match struct {
	ID            SessionID
	Hint          BreachHint
	EncryptedBlob []byte
}

func (d *DB) FindMatches(blockHints []BreachHint) ([]*Match, error) {
	var matches []*Match
	err := d.View(func(tx *bolt.Tx) error {
		hints := tx.Bucket(hintBucket)
		if hints == nil {
			return nil
		}

		for _, hint := range blockHints {
			hintSessions := hints.Bucket(hint[:])
			if hintSessions == nil {
				continue
			}

			err := hintSessions.ForEach(func(id, blob []byte) error {
				match := &Match{
					Hint:          hint,
					EncryptedBlob: make([]byte, len(blob)),
				}
				copy(match.ID[:], id)
				copy(match.EncryptedBlob, blob)

				matches = append(matches, match)

				return nil
			})
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return matches, nil
}

func (d *DB) ListEntries() error {
	return d.View(func(tx *bolt.Tx) error {
		hints := tx.Bucket(hintBucket)
		if hints == nil {
			return ErrCorruptTxnDB
		}

		return hints.ForEach(func(hint, _ []byte) error {
			hintSessions := tx.Bucket(hint)
			if hintSessions == nil {
				return ErrCorruptTxnDB
			}

			return hintSessions.ForEach(func(id, blob []byte) error {
				fmt.Printf("hint=%s, session_id=%s, blob=%s\n",
					hint, id, blob)
				return nil
			})
		})
	})
}

func (d *DB) Wipe() error {
	return d.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket(hintBucket)
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

func getSessionInfo(tx *bolt.Tx, sessionID *SessionID) (*SessionInfo, error) {
	sessions := tx.Bucket(sessionBucket)
	if sessions == nil {
		return nil, ErrCorruptTxnDB
	}

	infoBytes := sessions.Get(sessionID[:])
	if infoBytes == nil {
		return nil, ErrSessionNotFound
	}

	info := &SessionInfo{
		ID: *sessionID,
	}

	fmt.Printf("decoding session info\n")
	err := info.Decode(bytes.NewReader(infoBytes))
	if err != nil {
		fmt.Printf("unable to decode session info: %v\n", err)
		return nil, err
	}

	return info, nil
}

func putSessionInfo(tx *bolt.Tx, info *SessionInfo, isInit bool) error {
	sessions := tx.Bucket(sessionBucket)
	if sessions == nil {
		return ErrCorruptTxnDB
	}

	if isInit {
		infoBytes := sessions.Get(info.ID[:])
		if infoBytes != nil {
			return ErrSessionAlreadyExists
		}
	}

	fmt.Printf("encoding session info\n")
	var b bytes.Buffer
	if err := info.Encode(&b); err != nil {
		fmt.Printf("unable to encode session info: %v\n", err)
		return err
	}

	return sessions.Put(info.ID[:], b.Bytes())
}
