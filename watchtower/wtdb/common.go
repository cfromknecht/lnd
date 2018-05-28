package wtdb

import (
	"os"
	"path/filepath"

	"github.com/coreos/bbolt"
)

const (
	boltFilePermission = 0600
	byteOrder          = binary.BigEndian
)

// createDB
func createDB(dbPath, dbName string) (*bolt.DB, error) {
	if !fileExists(dbPath) {
		if err := os.MkdirAll(dbPath, 0700); err != nil {
			return nil, err
		}
	}

	dbFile := filepath.Join(dbPath, dbName)

	return bolt.Open(dbFile, boltFilePermission, nil)
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

var errBucketNotEmpty = errors.New("bucket not empty")

func isBucketEmpty(bucket *bolt.Bucket) error {
	return bucket.ForEach(func(_, _ []byte) error {
		return errBucketNotEmpty
	})
}
