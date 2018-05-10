package blockinspector

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/lightningnetwork/lnd/watchtower/punisher"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/lightningnetwork/lnd/watchtower/wtwire"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/wire"
	_ "github.com/roasbeef/btcwallet/walletdb/bdb"
)

// BlockInspector will check any incoming blocks agains the
// transactions found in the database, and in case of matches
// send the information needed to create a penalty transaction
// to the punisher.
type BlockInspector struct {
	started  int32 // atomic
	shutdown int32 // atomic

	cfg *Config

	wg   sync.WaitGroup
	quit chan struct{}
}

type BlobDecrypter interface {
	DecryptBlob([]byte, wtwire.BreachKey) ([]byte, error)
}

type Config struct {
	NewBlocks <-chan *wire.MsgBlock
	DB        *wtdb.DB
	Punisher  punisher.Punisher
	Decrypter BlobDecrypter
}

func New(cfg *Config) *BlockInspector {
	return &BlockInspector{
		cfg:  cfg,
		quit: make(chan struct{}),
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
		case block := <-c.cfg.NewBlocks:
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

	numTxnsInBlock := len(block.Transactions)

	hintToTx := make(map[wtwire.BreachHint]*wire.MsgTx, numTxnsInBlock)
	txHints := make([]wtwire.BreachHint, 0, numTxnsInBlock)

	for _, tx := range block.Transactions {
		fmt.Println("tx:", tx.TxHash())
		hash := tx.TxHash()
		hint := wtwire.NewBreachHintFromHash(&hash)

		txHints = append(txHints, hint)
		hintToTx[hint] = tx
	}

	// Check each tx in the block against the prefixes in the db.
	matches, err := c.cfg.DB.FindMatches(txHints)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, match := range matches {
		commitTx, ok := hintToTx[match.Hint]
		if !ok {
			fmt.Println("match not in tx id map!")
			return
		}

		fmt.Println("match", match)

		c.wg.Add(1)
		go c.handleMatch(commitTx, match)
	}
}

func (c *BlockInspector) handleMatch(commitTx *wire.MsgTx, match *wtdb.Match) {
	defer c.wg.Done()

	info, err := c.cfg.DB.GetSessionInfo(&match.ID)
	if err != nil {
		fmt.Printf("unable to get session info: %v\n", err)
		return
	}

	commitTxID := commitTx.TxHash()
	breachKey := wtwire.NewBreachKeyFromHash(&commitTxID)

	sweep, err := wtwire.DecryptSweepDetails(
		match.EncryptedBlob, breachKey, info.Version,
	)
	if err != nil {
		fmt.Printf("unable to decrypt blob: %v\n", err)
		return
	}

	p := &punisher.PunishInfo{
		BreachedCommitmentTx: commitTx,
		//RevocationBasePoint:   info.RevocationBasePoint,
		//LocalDelayedBasePoint: info.LocalDelayedBasePoint,
		CsvDelay:          info.CsvDelay,
		FeeRate:           info.FeeRate,
		OutputScript:      info.OutputScript,
		TowerReward:       info.OutputReward,
		TowerOutputScript: info.TowerOutputScript,
		Revocation:        sweep.Revocation,
		PenaltySignature:  sweep.SweepSig,
	}

	if err := c.cfg.Punisher.Punish(p); err != nil {
		fmt.Println(err)
		return
	}

}
