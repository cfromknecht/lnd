package neutrinoblocks

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/lightninglabs/neutrino"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/chainntnfs/neutrinonotify"
	"github.com/roasbeef/btcd/wire"
)

// Blocks is a simple service that will notify about new blocks
// added to the blockchain.
type Blocks struct {
	started  int32 // atomic
	shutdown int32 // atomic

	// Use block queue
	NewBlocks chan *wire.MsgBlock

	chainService  *neutrino.ChainService
	chainNotifier chainntnfs.ChainNotifier

	wg sync.WaitGroup

	quit chan struct{}
}

func New(chainService *neutrino.ChainService) (*Blocks, error) {
	return &Blocks{
		NewBlocks:    make(chan *wire.MsgBlock),
		chainService: chainService,
		quit:         make(chan struct{}),
	}, nil
}

func (b *Blocks) Start() error {
	if !atomic.CompareAndSwapInt32(&b.started, 0, 1) {
		return nil
	}

	b.chainService.Start()

	var err error
	b.chainNotifier, err = neutrinonotify.New(b.chainService)
	if err != nil {
		return err
	}
	if err := b.chainNotifier.Start(); err != nil {
		return err
	}

	b.wg.Add(1)
	go b.watch()

	return nil
}

func (b *Blocks) Stop() error {
	if !atomic.CompareAndSwapInt32(&b.shutdown, 0, 1) {
		return nil
	}

	b.chainNotifier.Stop()
	b.chainService.Stop()

	close(b.quit)
	b.wg.Wait()

	return nil
}

func (b *Blocks) watch() {
	defer b.wg.Done()

	events, err := b.chainNotifier.RegisterBlockEpochNtfn()
	if err != nil {
		fmt.Println("could not register for epoch", err)
		return
	}
	for {
		select {
		case e, ok := <-events.Epochs:
			if !ok {
				return
			}

			block, err := b.chainService.GetBlockFromNetwork(*e.Hash)
			if err != nil {
				fmt.Println(err)
				return
			}
			select {
			case b.NewBlocks <- block.MsgBlock():
			case <-b.quit:
				return
			}
		case <-b.quit:
			return
		}
	}
}
