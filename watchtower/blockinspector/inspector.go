package blockinspector

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/lightninglabs/sauron/punisher"
	"github.com/lightninglabs/sauron/transactiondb"
	"github.com/lightninglabs/sauron/wtwire"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/wire"
	_ "github.com/roasbeef/btcwallet/walletdb/bdb"
)

type match struct {
	SessionID     uint64
	DecryptionKey chainhash.Hash
	CommitTx      *wire.MsgTx
	EncryptedBlob []byte
}

// BlockInspector will check any incoming blocks agains the
// transactions found in the database, and in case of matches
// send the information needed to create a penalty transaction
// to the punisher.
type BlockInspector struct {
	started  int32 // atomic
	shutdown int32 // atomic

	db       *transactiondb.DB
	blocks   <-chan *wire.MsgBlock
	punisher *punisher.Punisher

	wg   sync.WaitGroup
	quit chan struct{}
}

func New(newBlocks <-chan *wire.MsgBlock,
	db *transactiondb.DB, p *punisher.Punisher) *BlockInspector {
	return &BlockInspector{
		db:       db,
		blocks:   newBlocks,
		punisher: p,
		quit:     make(chan struct{}),
	}
}

func (c *BlockInspector) Start() error {
	if !atomic.CompareAndSwapInt32(&c.started, 0, 1) {
		return nil
	}

	c.wg.Add(1)
	go c.watchBlocks()

	return nil
}

func (c *BlockInspector) Stop() error {
	if !atomic.CompareAndSwapInt32(&c.shutdown, 0, 1) {
		return nil
	}

	close(c.quit)
	c.wg.Wait()

	return nil
}

func (c *BlockInspector) watchBlocks() {
	defer c.wg.Done()
	for {
		select {
		case block := <-c.blocks:
			fmt.Println("new block;", block)

			c.wg.Add(1)
			go c.processNewBlock(block)
		case <-c.quit:
			return
		}
	}
}

func (c *BlockInspector) processNewBlock(block *wire.MsgBlock) {
	defer c.wg.Done()

	// Check each tx in the block against the prefixes in the db.
	var txPrefixes [][16]byte

	// Map from string(prefix) to TX.
	txs := make(map[string]*wire.MsgTx)
	for _, tx := range block.Transactions {
		fmt.Println("tx:", tx.TxHash())
		hash := tx.TxHash()
		var prefix [16]byte
		copy(prefix[:], hash[0:16])
		txPrefixes = append(txPrefixes, prefix)
		txs[string(prefix[:])] = tx
	}

	matches, err := c.db.FindMatches(txPrefixes)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, m := range matches {
		tx, ok := txs[string(m.TxIDPrefix[:])]
		if !ok {
			fmt.Println("match not in tx id map!")
			return
		}
		fmt.Println("match", m)
		hit := &match{
			SessionID:     m.SessionID,
			DecryptionKey: tx.TxHash(),
			CommitTx:      tx,
			EncryptedBlob: m.EncryptedBlob[:],
		}
		c.wg.Add(1)
		go c.handleMatch(hit)
	}
}

func (c *BlockInspector) handleMatch(m *match) {
	defer c.wg.Done()

	sweep, err := wtwire.DecryptSweepDetails(m.EncryptedBlob,
		&m.DecryptionKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	info, err := c.db.GetSessionInfo(m.SessionID)
	if err != nil {
		fmt.Println(err)
		return
	}

	p := &punisher.PunishInfo{
		BreachedCommitmentTx:  m.CommitTx,
		RevocationBasePoint:   info.RevocationBasePoint,
		LocalDelayedBasePoint: info.LocalDelayedBasePoint,
		CsvDelay:              info.CsvDelay,
		FeeRate:               info.FeeRate,
		OutputScript:          info.OutputScript,
		TowerReward:           info.OutputReward,
		TowerOutputScript:     info.TowerOutputScript,
		Revocation:            sweep.Revocation,
		PenaltySignature:      sweep.SweepSig,
	}
	if err := c.punisher.PunishBreach(p); err != nil {
		fmt.Println(err)
		return
	}

}
