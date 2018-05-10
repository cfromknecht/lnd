package watchtower

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	flags "github.com/btcsuite/go-flags"
	"github.com/lightninglabs/neutrino"
	"github.com/lightningnetwork/lnd/watchtower/blockinspector"
	"github.com/lightningnetwork/lnd/watchtower/config"
	"github.com/lightningnetwork/lnd/watchtower/neutrinoblocks"
	"github.com/lightningnetwork/lnd/watchtower/punisher"
	"github.com/lightningnetwork/lnd/watchtower/server"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/roasbeef/btcutil"
	"github.com/roasbeef/btcwallet/walletdb"
)

const (
	defaultLogFilename = "wt.log"
)

var (
	shutdownChannel = make(chan struct{})
)

func wtMain() error {

	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	fmt.Println(cfg)
	fmt.Println(cfg.Bitcoin)
	fmt.Println(cfg.Litecoin)
	fmt.Println(cfg.Bitcoin.Params.Name)

	address, err := btcutil.DecodeAddress(cfg.RewardAddress, cfg.Bitcoin.Params)
	if err != nil {
		return err
	}

	initLogRotator(filepath.Join(cfg.LogDir, defaultLogFilename))
	txDB, err := wtdb.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	fmt.Println("opened db", txDB)

	// First we'll open the database file for neutrino, creating
	// the database if needed.
	dbName := filepath.Join(cfg.DataDir, "neutrino.db")
	nodeDatabase, err := walletdb.Create("bdb", dbName)
	if err != nil {
		return err
	}

	// With the database open, we can now create an instance of the
	// neutrino light client. We pass in relevant configuration
	// parameters required.
	neutrinoCfg := neutrino.Config{
		DataDir:      cfg.DataDir,
		Database:     nodeDatabase,
		ChainParams:  *cfg.Bitcoin.Params,
		AddPeers:     cfg.NeutrinoMode.AddPeers,
		ConnectPeers: cfg.NeutrinoMode.ConnectPeers,
	}
	neutrino.WaitForMoreCFHeaders = time.Second * 1
	neutrino.MaxPeers = 8
	neutrino.BanDuration = 5 * time.Second
	svc, err := neutrino.NewChainService(neutrinoCfg)
	if err != nil {
		return fmt.Errorf("unable to create neutrino: %v", err)
	}
	svc.Start()

	// TODO: multinet
	blocks, err := neutrinoblocks.New(svc)
	if err != nil {
		return err
	}
	if err := blocks.Start(); err != nil {
		return err
	}

	punisher, err := punisher.New(svc)
	if err != nil {
		return err
	}

	watcher := blockinspector.New(&blockinspector.Config{
		NewBlocks: blocks.NewBlocks,
		DB:        txDB,
		Punisher:  punisher,
	})
	if err := watcher.Start(); err != nil {
		return err
	}
	fmt.Println("watcher started")

	// Serve incoming connections, add to db.
	privKey := config.ServerPrivKey
	fmt.Println("server privKey: ", hex.EncodeToString(privKey.Serialize()))
	listenAddrs := []string{"localhost:9777"}
	server, err := server.New(listenAddrs, privKey, txDB, address)
	if err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}
	fmt.Println("server started")

	// Watch incoming blocks, compare with db.
	addInterruptHandler(func() {
		fmt.Println("Gracefully shutting down...")
		watcher.Stop()
	})

	// Wait for shutdown signal from either a graceful server stop or from
	// the interrupt handler.
	<-shutdownChannel
	fmt.Println("Shutdown complete")
	return nil
}

func main() {
	// Use all processor cores.
	// TODO(roasbeef): remove this if required version # is > 1.6?
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Call the "real" main in a nested manner so the defers will properly
	// be executed in the case of a graceful shutdown.
	if err := wtMain(); err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
