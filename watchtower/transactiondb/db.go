package transactiondb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coreos/bbolt"
	"github.com/lightningnetwork/lnd/watchtower/wtwire"
)

const (
	dbName           = "txdb.db"
	dbFilePermission = 0600
)

var (
	hintBucket    = []byte("hint-to-sessions")
	blobBucket    = []byte("session-hint-to-blob")
	sessionBucket = []byte("session-to-info")

	// Big endian is the preferred byte order, due to cursor scans over
	// integer keys iterating in order.
	byteOrder = binary.BigEndian

	ErrCorruptTxnDB = errors.New("transaction db is corrupted")

	ErrSessionNotFound = errors.New("session not found in db")
)

type DB struct {
	*bolt.DB
	dbPath string
}

func Open(dbPath string) (*DB, error) {
	path := filepath.Join(dbPath, dbName)

	if !fileExists(path) {
		if err := createDB(dbPath); err != nil {
			return nil, err
		}
	}

	bdb, err := bolt.Open(path, dbFilePermission, nil)
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
		_, err = tx.CreateBucketIfNotExists(blobBucket)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(sessionBucket)
		return err
	})
}

func (d *DB) InsertSessionInfo(info *wtwire.SessionInfo) error {
	var key [8]byte
	byteOrder.PutUint64(key[:], info.SessionID)

	return d.DB.Batch(func(tx *bolt.Tx) error {
		sessions := tx.Bucket(sessionBucket)
		if sessions == nil {
			return ErrCorruptTxnDB
		}

		var b bytes.Buffer
		if err := info.Encode(&b, 0); err != nil {
			return err
		}

		return sessions.Put(key[:], b.Bytes())
	})
}

func (d *DB) GetSessionInfo(sessionID uint64) (*wtwire.SessionInfo, error) {
	var key [8]byte
	byteOrder.PutUint64(key[:], sessionID)

	var info *wtwire.SessionInfo
	err := d.View(func(tx *bolt.Tx) error {
		sessions := tx.Bucket(sessionBucket)
		if sessions == nil {
			return ErrCorruptTxnDB
		}

		infoBytes := sessions.Get(key[:])
		if infoBytes == nil {
			return ErrSessionNotFound
		}

		info = &wtwire.SessionInfo{}

		return info.Decode(bytes.NewReader(infoBytes), 0)
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

func (d *DB) InsertTransaction(blob *wtwire.StateUpdate) error {
	return d.Batch(func(tx *bolt.Tx) error {
		blobs := tx.Bucket(blobBucket)
		if blobs == nil {
			return ErrCorruptTxnDB
		}

		fmt.Printf("storing blob: %s\n", string(blob.EncryptedBlob))

		return blobs.Put(blob.TxIDPrefix[:], blob.EncryptedBlob)
	})
}

func (d *DB) ListEntries() error {
	return d.View(func(tx *bolt.Tx) error {
		blobs := tx.Bucket(blobBucket)
		if blobs == nil {
			return ErrCorruptTxnDB
		}

		return blobs.ForEach(func(k, v []byte) error {
			fmt.Printf("key=%s, value=%s\n", k, v)
			return nil
		})
	})
}

func (d *DB) FindMatches(
	hints []wtwire.BreachHint) ([]*wtwire.StateUpdate, error) {

	var matches []*wtwire.StateUpdate
	err := d.View(func(tx *bolt.Tx) error {
		blobs := tx.Bucket(blobBucket)
		if blobs == nil {
			return nil
		}

		for _, hint := range hints {
			blobBytes := blobs.Get(hint[:])
			if blobBytes == nil {
				continue
			}

			update := &wtwire.StateUpdate{
				TxIDPrefix:    hint,
				EncryptedBlob: make([]byte, len(blobBytes)),
			}
			copy(update.EncryptedBlob, blobBytes)

			matches = append(matches, update)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}

func (d *DB) Wipe() error {
	return d.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket(hintBucket)
		if err != nil && err != bolt.ErrBucketNotFound {
			return err
		}
		err = tx.DeleteBucket(blobBucket)
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

func createDB(dbPath string) error {
	if !fileExists(dbPath) {
		if err := os.MkdirAll(dbPath, 0700); err != nil {
			return err
		}
	}

	path := filepath.Join(dbPath, dbName)
	bdb, err := bolt.Open(path, dbFilePermission, nil)
	if err != nil {
		return err
	}

	if err != nil {
		return fmt.Errorf("unable to create new db")
	}

	return bdb.Close()
}

// fileExists returns true if the file exists, and false otherwise.
func fileExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}
