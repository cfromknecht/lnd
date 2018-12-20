package wtclient

import (
	"container/list"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/lightningnetwork/lnd/watchtower/wtserver"
	"github.com/lightningnetwork/lnd/watchtower/wtwire"
)

const retryInterval = 2 * time.Second

type SessionQueueConfig struct {
	ClientSession *wtdb.ClientSessionInfo
	SweepAddress  []byte
	Dial          func(*btcec.PrivateKey,
		*lnwire.NetAddress) (wtserver.Peer, error)
	SendMessage func(wtserver.Peer, wtwire.Message) error
	ReadMessage func(wtserver.Peer) (wtwire.Message, error)
	Signer      lnwallet.Signer
	DB          DB
}

type SessionQueueSet map[wtdb.SessionID]*SessionQueue

func (s *SessionQueueSet) Add(sessionQueue *SessionQueue) {
	(*s)[*sessionQueue.ID()] = sessionQueue
}

func (s *SessionQueueSet) ApplyAndWait(getApply func(*SessionQueue) func()) {
	var wg sync.WaitGroup
	for _, sq := range *s {
		wg.Add(1)
		go func(sessionQueue *SessionQueue) {
			defer wg.Done()
			getApply(sessionQueue)()
		}(sq)
	}
	wg.Wait()
}

type SessionQueue struct {
	started uint32 // to be used atomically
	stopped uint32 // to be used atomically
	forced  uint32 // to be used atomically
	logged  uint32 // to be used atomically

	cfg *SessionQueueConfig

	queue     *list.List
	queueMtx  sync.Mutex
	queueCond *sync.Cond

	seqNum      uint16
	lastApplied uint16

	localInit *wtwire.Init
	towerAddr *lnwire.NetAddress

	quit      chan struct{}
	forceQuit chan struct{}
	shutdown  chan struct{}
}

func newSessionQueue(cfg *SessionQueueConfig) *SessionQueue {
	localInit := wtwire.NewInitMessage(
		lnwire.NewRawFeatureVector(),
		lnwire.NewRawFeatureVector(wtwire.WtSessionsRequired),
	)

	towerAddr := &lnwire.NetAddress{
		IdentityKey: cfg.ClientSession.Tower.IdentityKey,
		Address:     cfg.ClientSession.Tower.Addresses[0],
	}

	sq := &SessionQueue{
		cfg:       cfg,
		queue:     list.New(),
		localInit: localInit,
		towerAddr: towerAddr,
		quit:      make(chan struct{}),
		forceQuit: make(chan struct{}),
		shutdown:  make(chan struct{}),
	}
	sq.queueCond = sync.NewCond(&sq.queueMtx)

	return sq
}

func (q *SessionQueue) Start() error {
	if !atomic.CompareAndSwapUint32(&q.started, 0, 1) {
		return nil
	}

	go q.sessionManager()

	return nil
}

func (q *SessionQueue) Stop() {
	if !atomic.CompareAndSwapUint32(&q.stopped, 0, 1) {
		return
	}

	close(q.quit)
	q.signalUntilShutdown()

	if !atomic.CompareAndSwapUint32(&q.logged, 0, 1) {
		return
	}

	log.Infof("Session queue %s successfully stopped", q.ID())
}

func (q *SessionQueue) ForceQuit() {
	if !atomic.CompareAndSwapUint32(&q.forced, 0, 1) {
		return
	}

	close(q.forceQuit)
	q.signalUntilShutdown()

	if !atomic.CompareAndSwapUint32(&q.logged, 0, 1) {
		return
	}

	log.Infof("Session queue %s force quit", q.ID())
}

func (q *SessionQueue) ID() *wtdb.SessionID {
	return &q.cfg.ClientSession.ID
}

type ReserveStatus uint8

const (
	ReserveAvailable ReserveStatus = iota
	ReserveExhausted
)

// AcceptTask ...
func (q *SessionQueue) AcceptTask(task *backupTask) (ReserveStatus, bool) {
	q.queueCond.L.Lock()

	// Examine the current reserve status of the session queue.
	curStatus := q.reserveStatus()
	switch curStatus {

	// The session queue is exhausted, and cannot accept the task because it
	// is full. Reject the task such that it can be tried against a
	// different session.
	case ReserveExhausted:
		q.queueCond.L.Unlock()
		return curStatus, false

	// The session queue is not exhausted. Compute the sweep and reward
	// outputs as a function of the session parameters. If the outputs are
	// dusty or uneconomical to backup, the task is rejected and will not be
	// tried again.
	//
	// TODO(conner): queue backups and retry with different session params.
	case ReserveAvailable:
		err := task.assignSession(q.cfg.ClientSession)
		if err != nil {
			q.queueCond.L.Unlock()
			return curStatus, false
		}
	}

	// The sweep and reward outputs satisfy the session's policy, queue the
	// task for final signing and delivery.
	q.queue.PushBack(task)

	// Finally, compute the session's *new* reserve status. This will be
	// used by the client to determine if it can continue using this session
	// queue, or if it should negotiate a new one.
	newStatus := q.reserveStatus()
	q.queueCond.L.Unlock()

	q.queueCond.Signal()

	return newStatus, true
}

func (q *SessionQueue) sessionManager() {
	defer close(q.shutdown)

	for {
		q.queueCond.L.Lock()
		for q.queue.Front() == nil {
			q.queueCond.Wait()

			select {
			case <-q.quit:
				if q.queue.Len() == 0 {
					return
				}
			case <-q.forceQuit:
				return
			default:
			}
		}
		q.queueCond.L.Unlock()

		// Initiate a new connection to the watchtower and attempt to
		// drain all pending tasks.
		q.dialAndDrain()
	}
}

func (q *SessionQueue) dialAndDrain() {
	log.Debugf("Dialing tower")

	// First, check that we are able to dial this session's tower.
	conn, err := q.cfg.Dial(q.cfg.ClientSession.SessionPrivKey, q.towerAddr)
	if err != nil {
		log.Errorf("Unable to dial watchtower at %v: %v",
			q.towerAddr, err)

		// TODO(conner): add exponential backoff?
		select {
		case <-time.After(retryInterval):
		case <-q.forceQuit:
		}
		return
	}
	defer conn.Close()

	sendInit := true
	for {
		// TODO(conner) batch multiple updates at a time
		q.queueCond.L.Lock()
		seqNum := q.seqNum
		next := q.queue.Front()
		task := next.Value.(*backupTask)
		isLast := q.queue.Len() == 1
		q.queueCond.L.Unlock()

		hint, encBlob, err := task.craftSessionPayload(
			q.cfg.SweepAddress, q.cfg.Signer,
		)
		if err != nil {
			// TODO(conner): mark will not send
			log.Debugf("Unable to create justice kit: %v", err)
			return
		}
		// TODO(conner): special case other obscure errors

		// Set the IsComplete flag if this is the last item in
		// our queue.
		var isComplete uint8
		if isLast {
			isComplete = 1
		}

		stateUpdate := &wtwire.StateUpdate{
			SeqNum:        seqNum + 1,
			LastApplied:   q.lastApplied,
			IsComplete:    isComplete,
			Hint:          hint,
			EncryptedBlob: encBlob,
		}

		log.Debugf("Sending state update seqnum: %d", stateUpdate.SeqNum)

		// TODO(conner): write task at session index
		err = q.cfg.DB.CommitBackup(
			task.chanID, task.commitHeight, q.ID(), stateUpdate,
		)
		if err != nil {
			// TODO(conner): mark failed/reschedule
			return
		}

		shouldBackoff, err := q.sendStateUpdate(
			conn, q.localInit, stateUpdate, sendInit,
		)
		if err != nil {
			log.Errorf("Unable to send state update: %v", err)

			var delay time.Duration
			if shouldBackoff {
				delay = retryInterval
			} else {
				delay = time.Millisecond
			}

			select {
			case <-time.After(delay):
			case <-q.forceQuit:
			}
			return
		}

		// If the last task was backed up successfully, we'll exit and
		// continue once more tasks are added to the queue.
		if isLast {
			return
		}

		// If the first state update was sent successfully, we can skip
		// sending an Init messages for subsequent updates.
		sendInit = false
	}
}

func (q *SessionQueue) sendStateUpdate(conn wtserver.Peer,
	localInit *wtwire.Init, stateUpdate *wtwire.StateUpdate,
	sendInit bool) (bool, error) {

	if sendInit {
		// Send Init to tower.
		err := q.cfg.SendMessage(conn, q.localInit)
		if err != nil {
			return false, err
		}

		// Receive Init from tower.
		remoteMsg, err := q.cfg.ReadMessage(conn)
		if err != nil {
			return false, err
		}

		remoteInit, ok := remoteMsg.(*wtwire.Init)
		if !ok {
			return true, err
		}

		// Validate Init.
		err = handleInit(q.localInit, remoteInit)
		if err != nil {
			return true, err
		}
	}

	// Send StateUpdate to tower.
	err := q.cfg.SendMessage(conn, stateUpdate)
	if err != nil {
		return false, err
	}

	// Receive StateUpdate from tower.
	remoteMsg, err := q.cfg.ReadMessage(conn)
	if err != nil {
		return false, err
	}

	stateUpdateReply, ok := remoteMsg.(*wtwire.StateUpdateReply)
	if !ok {
		return true, err
	}

	switch stateUpdateReply.Code {
	case wtwire.CodeOK:
		if stateUpdateReply.LastApplied > stateUpdate.SeqNum {
			// TODO(conner): borked watchtower?
		}

		// TODO(conner): validate last applied <= seqnum
		// TODO(conner): store last applied for session
		// TODO(conner): delete blob locally
		q.queueCond.L.Lock()
		q.seqNum++
		q.lastApplied = stateUpdateReply.LastApplied
		q.queue.Remove(q.queue.Front())
		q.queueCond.L.Unlock()

		return false, nil

	// TODO(conner): handle other error cases.

	default:
		return true, fmt.Errorf("received unknown error code %d",
			stateUpdateReply.Code)
	}
}

// NOTE: This method MUST be called with queueCond's exclusive lock held.
func (q *SessionQueue) reserveStatus() ReserveStatus {
	maxUpdates := q.cfg.ClientSession.Policy.MaxUpdates
	numPending := uint16(q.queue.Len())

	log.Debugf("seqnum=%d pending=%d max-updates=%d",
		q.seqNum, numPending, maxUpdates)

	if q.seqNum+numPending < maxUpdates {
		return ReserveAvailable
	}

	return ReserveExhausted

}

func (q *SessionQueue) signalUntilShutdown() {
	for {
		select {
		case <-time.After(time.Millisecond):
			q.queueCond.Signal()
		case <-q.shutdown:
			return
		}
	}
}
