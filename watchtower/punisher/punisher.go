package punisher

import (
	"errors"
	"fmt"

	"github.com/roasbeef/btcd/blockchain"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

var (
	ErrOutputNotFound = errors.New("unable to find output on commit tx")
)

type Config struct {
	SendTransaction func(*wire.MsgTx) error
}

type Punisher interface {
	Punish(*PunishInfo) error
}

type punisher struct {
	cfg *Config
}

func New(cfg *Config) *punisher {
	return &punisher{
		cfg: cfg,
	}
}

func (p *punisher) Punish(info *PunishInfo) error {
	penaltyTx, err := info.CreatePenaltyTx()
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println(penaltyTx)

	err = blockchain.CheckTransactionSanity(btcutil.NewTx(penaltyTx))
	if err != nil {
		return err
	}

	// TODO(conner): if broadcast successful, mark in db.

	return p.cfg.SendTransaction(penaltyTx)
}
