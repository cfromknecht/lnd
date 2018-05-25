package watchtower

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/lightninglabs/neutrino"
	"github.com/lightningnetwork/lnd/watchtower/config"
	"github.com/lightningnetwork/lnd/watchtower/lookout"
	"github.com/lightningnetwork/lnd/watchtower/neutrinoblocks"
	"github.com/lightningnetwork/lnd/watchtower/punisher"
	"github.com/lightningnetwork/lnd/watchtower/server"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcwallet/walletdb"
)

const (
	defaultLogFilename = "wt.log"
)

var (
	shutdownChannel = make(chan struct{})
)

type WatchTower struct {
	started uint32
	stopped uint32

	cfg *config.Config

	blocks  *neutrinoblocks.Blocks
	lookout *lookout.Lookout
	server  *server.Server
	txdb    *wtdb.DB
}

func New(cfg *config.Config) *WatchTower {
	return &WatchTower{
		cfg: cfg,
	}
}

func (w *WatchTower) Start() error {
	if !atomic.CompareAndSwapUint32(&w.started, 0, 1) {
		return nil
	}

	initLogRotator(filepath.Join(w.cfg.LogDir, defaultLogFilename))

	var err error
	w.txdb, err = wtdb.Open(w.cfg.DataDir)
	if err != nil {
		return err
	}
	fmt.Println("opened db", w.txdb)

	neutrinoDbPath := filepath.Join(w.cfg.DataDir, "chain")

	// Ensure that the neutrino db path exists.
	if err := os.MkdirAll(neutrinoDbPath, 0700); err != nil {
		return err
	}

	// First we'll open the database file for neutrino, creating
	// the database if needed.
	dbName := filepath.Join(neutrinoDbPath, "neutrino.db")
	nodeDatabase, err := walletdb.Create("bdb", dbName)
	if err != nil {
		w.txdb.Close()
		return err
	}

	// With the database open, we can now create an instance of the
	// neutrino light client. We pass in relevant configuration
	// parameters required.
	neutrinoCfg := neutrino.Config{
		DataDir:      neutrinoDbPath,
		Database:     nodeDatabase,
		ChainParams:  *w.cfg.Bitcoin.Params,
		AddPeers:     w.cfg.NeutrinoMode.AddPeers,
		ConnectPeers: w.cfg.NeutrinoMode.ConnectPeers,
	}
	neutrino.WaitForMoreCFHeaders = time.Second * 1
	neutrino.MaxPeers = 8
	neutrino.BanDuration = 5 * time.Second
	svc, err := neutrino.NewChainService(neutrinoCfg)
	if err != nil {
		w.txdb.Close()
		return fmt.Errorf("unable to create neutrino: %v", err)
	}

	w.blocks, err = neutrinoblocks.New(svc)
	if err != nil {
		w.txdb.Close()
		return err
	}

	w.lookout = lookout.New(&lookout.Config{
		NewBlocks: w.blocks.NewBlocks,
		DB:        w.txdb,
		Punisher: punisher.New(&punisher.Config{
			SendTransaction: func(tx *wire.MsgTx) error {
				return svc.SendTransaction(tx)
			},
		}),
	})

	// Serve incoming connections, add to db.
	privKey := config.ServerPrivKey
	fmt.Println("server privKey: ", hex.EncodeToString(privKey.Serialize()))
	listenAddrs := []string{"localhost:9777"}
	w.server, err = server.New(&server.Config{
		ListenAddrs: listenAddrs,
		NodePrivKey: privKey,
		DB:          w.txdb,
		//NewAddress
	})
	if err != nil {
		w.txdb.Close()
		return err
	}

	// TODO: multinet
	if err = w.blocks.Start(); err != nil {
		w.txdb.Close()
		return err
	}
	fmt.Println("blocks started")

	if err = w.lookout.Start(); err != nil {
		w.blocks.Stop()
		w.txdb.Close()
		return err
	}
	fmt.Println("lookout started")

	if err = w.server.Start(); err != nil {
		w.lookout.Stop()
		w.blocks.Stop()
		w.txdb.Close()
		return err
	}
	fmt.Println("server started")

	return nil
}

func (w *WatchTower) Stop() error {
	if !atomic.CompareAndSwapUint32(&w.stopped, 0, 1) {
		return nil
	}

	w.server.Stop()
	w.lookout.Stop()
	w.blocks.Stop()

	return w.txdb.Close()
}
