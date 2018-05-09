package blockinspector_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/watchtower/blockinspector"
	"github.com/lightningnetwork/lnd/watchtower/punisher"
	"github.com/lightningnetwork/lnd/watchtower/transactiondb"
	"github.com/lightningnetwork/lnd/watchtower/wtwire"
	"github.com/roasbeef/btcd/wire"
)

var (
	testPrefix1 = []byte("prefix1")
	testPrefix2 = []byte("prefix2")
	testBlob1   = bytes.Repeat([]byte("a"), 96)
	testBlob2   = bytes.Repeat([]byte("b"), 96)
)

type mockPunisher struct {
	matches chan *punisher.PunishInfo
}

func (p *mockPunisher) Punish(info *punisher.PunishInfo) error {
	p.matches <- info
	return nil
}

func makeArray32(i uint64) [32]byte {
	var arr [32]byte
	binary.BigEndian.PutUint64(arr[:], i)
	return arr
}

func makeArray64(i uint64) [64]byte {
	var arr [64]byte
	binary.BigEndian.PutUint64(arr[:], i)
	return arr
}

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
	matches := make(chan *punisher.PunishInfo)
	punisher := &mockPunisher{matches: matches}
	inspector := blockinspector.New(&blockinspector.Config{
		NewBlocks: blocks,
		DB:        db,
		Punisher:  punisher,
	})
	if err := inspector.Start(); err != nil {
		t.Fatalf("unable to start watcher: %v", err)
	}

	sessionInfo := &wtwire.SessionInfo{}
	err = db.InsertSessionInfo(sessionInfo)
	if err != nil {
		t.Fatalf("unable to insert session info: %v", err)
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	hash := tx.TxHash()
	fmt.Println("tx:", tx.TxHash())

	tx2 := wire.NewMsgTx(wire.TxVersion + 1)
	hash2 := tx2.TxHash()
	fmt.Println("tx:", tx2.TxHash())

	sweepDetail1 := &wtwire.SweepDetails{
		Revocation: makeArray32(1),
		SweepSig:   makeArray64(1),
	}

	sweepDetail2 := &wtwire.SweepDetails{
		Revocation: makeArray32(1),
		SweepSig:   makeArray64(1),
	}

	encBlob1, err := wtwire.EncryptSweepDetails(
		sweepDetail1, wtwire.NewBreachKeyFromHash(&hash),
	)
	if err != nil {
		t.Fatalf("unable to encrypt sweep detail 1: %v", err)
	}

	encBlob2, err := wtwire.EncryptSweepDetails(
		sweepDetail2, wtwire.NewBreachKeyFromHash(&hash2),
	)
	if err != nil {
		t.Fatalf("unable to encrypt sweep detail 2: %v", err)
	}

	// Add a few blobs to the database.
	var prefix1 [16]byte
	copy(prefix1[:], hash[:])
	var blob1 [wtwire.EncryptedBlobSize]byte
	copy(blob1[:], testBlob1)
	txBlob1 := &wtwire.StateUpdate{
		TxIDPrefix:    prefix1,
		EncryptedBlob: encBlob1,
	}
	if err := db.InsertTransaction(txBlob1); err != nil {
		t.Fatalf("unable to add tx to db: %v", err)
	}

	var prefix2 [16]byte
	copy(prefix2[:], hash2[:])
	var blob2 [wtwire.EncryptedBlobSize]byte
	copy(blob2[:], testBlob2)
	txBlob2 := &wtwire.StateUpdate{
		TxIDPrefix:    prefix2,
		EncryptedBlob: encBlob2,
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
	case hit := <-matches:
		fmt.Println(hit)
		txid := hit.BreachedCommitmentTx.TxHash()
		if !bytes.Equal(txid[:], hash[:]) {
			t.Fatalf("receivec decryption key dd not match tx1's txid")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("tx was not matched")
	}
}
