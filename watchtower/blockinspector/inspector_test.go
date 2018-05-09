package blockinspector_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/lightninglabs/sauron/blockinspector"
	"github.com/lightninglabs/sauron/transactiondb"
	"github.com/lightninglabs/sauron/wtwire"
	"github.com/roasbeef/btcd/wire"
)

var (
	testPrefix1 = []byte("prefix1")
	testPrefix2 = []byte("prefix2")
	testBlob1   = []byte("encrypted blob numeor uno")
	testBlob2   = []byte("encrypted blob numeor dos")
)

func TestMatchingTransactions(t *testing.T) {
	testDir, err := ioutil.TempDir("", "testcreate")
	if err != nil {
		t.Fatalf("unable to create temp directory: %v", err)
	}
	defer func() {
		os.RemoveAll(testDir)
	}()

	db, err := transactiondb.Open(testDir)
	if err != nil {
		t.Fatalf("unable to open transaction db: %v", err)
	}
	blocks := make(chan *wire.MsgBlock)
	inspector := blockinspector.New(blocks, db)
	if err := watcher.Start(); err != nil {
		t.Fatalf("unable to start watcher: %v", err)
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	hash := tx.TxHash()
	fmt.Println("tx:", tx.TxHash())

	tx2 := wire.NewMsgTx(wire.TxVersion + 1)
	hash2 := tx2.TxHash()
	fmt.Println("tx:", tx2.TxHash())

	// Add a few blobs to the database.
	var prefix1 [16]byte
	copy(prefix1[:], hash[:])
	var blob1 [wtwire.EncryptedBlobSize]byte
	copy(blob1[:], testBlob1)
	txBlob1 := &wtwire.TxBlob{
		TxIDPrefix:    prefix1,
		EncryptedBlob: blob1,
	}
	if err := db.InsertTransaction(txBlob1); err != nil {
		t.Fatalf("unable to add tx to db: %v", err)
	}

	var prefix2 [16]byte
	copy(prefix2[:], hash2[:])
	var blob2 [wtwire.EncryptedBlobSize]byte
	copy(blob2[:], testBlob2)
	txBlob2 := &wtwire.TxBlob{
		TxIDPrefix:    prefix2,
		EncryptedBlob: blob2,
	}
	if err := db.InsertTransaction(txBlob2); err != nil {
		t.Fatalf("unable to add tx to db: %v", err)
	}

	// make block containging transaction matching the first prefix
	block := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{tx},
	}
	blocks <- block

	// This should trigger dispatch of the justice kit for the first tx
	select {
	case hit := <-watcher.TxHits:
		fmt.Println(hit)
		if !bytes.Equal(hit.DecryptionKey[:], hash[:]) {
			t.Fatalf("receivec decryption key dd not match tx1's txid")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("tx was not matched")
	}
}
