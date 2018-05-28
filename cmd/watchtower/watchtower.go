package main

import (
	"fmt"
	"os"

	flags "github.com/btcsuite/go-flags"
	"github.com/lightningnetwork/lnd/watchtower"
	"github.com/lightningnetwork/lnd/watchtower/config"
)

var shutdownChannel = make(chan struct{})

func wtMain() error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	fmt.Println(cfg)
	fmt.Println(cfg.Bitcoin)
	fmt.Println(cfg.Litecoin)
	fmt.Println(cfg.Bitcoin.Params.Name)

	watchTower := watchtower.New(cfg)

	err = watchTower.Start()
	if err != nil {
		return err
	}
	defer watchTower.Stop()

	// Watch incoming blocks, compare with db.
	addInterruptHandler(func() {
		fmt.Println("Gracefully shutting down...")
		watchTower.Stop()
	})

	// Wait for shutdown signal from either a graceful server stop or from
	// the interrupt handler.
	<-shutdownChannel
	fmt.Println("Shutdown complete")
	return nil
}

func main() {
	// Call the "real" main in a nested manner so the defers will properly
	// be executed in the case of a graceful shutdown.
	err := wtMain()
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
