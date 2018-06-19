package client

import (
	"sync"

	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
)

type BackupReceipt struct {
	id     wtdb.SessionID
	seqnum uint16
}

type ChannelGuard struct {
	mu sync.RWMutex

	params []*wtdb.BackupParams

	privateTracker backupTracker
	publicTracker  backupTracker
}

type backupState byte

const (
	backupStateCommitted backupState = iota
	backupStatePending
	backupStateAcked
)

type backupTracker map[uint64]map[BackupReceipt]backupState

func (b backupTracker) setState(height uint64, receipt *BackupReceipt,
	state backupState) {

	if _, ok := b[height]; !ok {
		b[height] = make(map[BackupReceipt]backupState)
	}
	b[height][*receipt] = state
}

func NewChannelGuard(params []*wtdb.BackupParams) (*ChannelGuard, error) {
	if len(params) == 0 {
		return nil, fmt.Errorf("must provide non-zero number of params")
	}

	return &ChannelGuard{
		privateTracker: make(backupTracker),
		publicTracker:  make(backupTracker),
	}, nil
}

func (c *ChannelGuard) CurrentParams() *wtdb.BackupParams {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.currentParams()
}

func (c *ChannelGuard) currentParams() *wtdb.BackupParams {
	return c.params[len(c.params)-1]
}

func (c *ChannelGuard) RegisterReceipt(
	height uint64,
	receipt *BackupReceipt,
	private bool) {

	c.mu.Lock()
	defer c.mu.Unlock()

	var tracker backupTracker
	if private {
		tracker = c.privateTracker
	} else {
		tracker = c.publicTracker
	}

	return tracker.setState(height, receipt, backupStateCommitted)
}

func (c *ChannelGuard) SetPendingReceipt(
	height uint64,
	receipt *BackupReceipt,
	private bool) {

	c.mu.Lock()
	defer c.mu.Unlock()

	var tracker backupTracker
	if private {
		tracker = c.privateTracker
	} else {
		tracker = c.publicTracker
	}

	return tracker.setState(height, receipt, backupStatePending)
}

func (c *ChannelGuard) AckReceipt(
	height uint64,
	receipt *BackupReceipt,
	private bool) error {

	c.mu.Lock()
	defer c.mu.Unlock()

	var tracker backupTracker
	if private {
		tracker = c.privateTracker
	} else {
		tracker = c.publicTracker
	}

	return tracker.setState(height, receipt, backupStateAcked)
}

type BackupContext struct {
	// Add channel backup params
	State       *wtdb.RevokedState
	Retribution *lnwallet.BreachRetribution

	Guard *ChannelGuard
}

func (c *BackupContext) RegisterBackup(receipt *BackupReceipt, private bool) {
	return c.Guard.RegisterReceipt(c.State.CommitHeight, receipt, private)
}

func (c *BackupContext) SetPendingBackup(receipt *BackupReceipt, private bool) {
	return c.Guard.SetPendingReceipt(c.State.CommitHeight, receipt, private)
}

func (c *BackupContext) AckBackup(receipt *BackupReceipt, private bool) {
	return c.Guard.AckReceipt(c.State.CommitHeight, receipt, private)
}
