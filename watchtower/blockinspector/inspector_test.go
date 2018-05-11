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
	"github.com/lightningnetwork/lnd/watchtower/sweep"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
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

func makeArray33(i uint64) [33]byte {
	var arr [33]byte
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

	db, err := wtdb.Open(testDir)
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

	sessionInfo1 := &wtdb.SessionInfo{
		ID:         makeArray33(1),
		MaxUpdates: 10,
	}
	err = db.InsertSessionInfo(sessionInfo1)
	if err != nil {
		t.Fatalf("unable to insert session info: %v", err)
	}

	sessionInfo2 := &wtdb.SessionInfo{
		ID:         makeArray33(2),
		MaxUpdates: 10,
	}
	err = db.InsertSessionInfo(sessionInfo2)
	if err != nil {
		t.Fatalf("unable to insert session info: %v", err)
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	hash := tx.TxHash()
	fmt.Println("tx:", tx.TxHash())

	tx2 := wire.NewMsgTx(wire.TxVersion + 1)
	hash2 := tx2.TxHash()
	fmt.Println("tx:", tx2.TxHash())

	sweepDesc1 := &sweep.Descriptor{
		Params: sweep.StaticScriptParams{
			RevocationPubKey: makeArray33(1),
			LocalDelayPubKey: makeArray33(1),
			CSVDelay:         144,
		},
	}
	sweepDesc2 := &sweep.Descriptor{
		Params: sweep.StaticScriptParams{
			RevocationPubKey: makeArray33(2),
			LocalDelayPubKey: makeArray33(2),
			CSVDelay:         144,
		},
	}

	breachKey1 := wtdb.NewBreachKeyFromHash(&hash)
	encBlob1, err := sweepDesc1.Encrypt(breachKey1[:], 0)
	if err != nil {
		t.Fatalf("unable to encrypt sweep detail 1: %v", err)
	}

	breachKey2 := wtdb.NewBreachKeyFromHash(&hash2)
	encBlob2, err := sweepDesc2.Encrypt(breachKey2[:], 0)
	if err != nil {
		t.Fatalf("unable to encrypt sweep detail 2: %v", err)
	}

	// Add a few blobs to the database.
	txBlob1 := &wtdb.SessionStateUpdate{
		ID:            makeArray33(1),
		Hint:          wtdb.NewBreachHintFromHash(&hash),
		EncryptedBlob: encBlob1,
		SeqNum:        1,
	}
	if err := db.InsertStateUpdate(txBlob1); err != nil {
		t.Fatalf("unable to add tx to db: %v", err)
	}

	txBlob2 := &wtdb.SessionStateUpdate{
		ID:            makeArray33(2),
		Hint:          wtdb.NewBreachHintFromHash(&hash2),
		EncryptedBlob: encBlob2,
		SeqNum:        1,
	}
	if err := db.InsertStateUpdate(txBlob2); err != nil {
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
