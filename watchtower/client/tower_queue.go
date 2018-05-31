package client

import (
	"container/list"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lightninglabs/sauron/wtwire"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
)

var (
	ErrTowerQueueShuttingDown = errors.New("tower queue shutting down")
)

type TowerQueue struct {
	started uint32
	stopped uint32
	forced  uint32

	tower *wtdb.Tower

	batchInterval time.Time
	batchReady    chan *UpdateBatch

	updateMtx  sync.RWMutex
	updateCond *sync.Cond
	updates    *list.List

	force    chan struct{}
	quit     chan struct{}
	shutdown chan struct{}
}

func NewTowerQueue(tower *wtdb.Tower, interval time.Time,
	batchReady chan *UpdateBatch) *TowerQueue {

	towerQueue := &TowerQueue{
		batchInterval: interval,
		batchReady:    make(chan *UpdateBatch),
		updates:       list.New(),
		force:         make(chan struct{}),
		quit:          make(chan struct{}),
		shutdown:      make(chan struct{}),
	}
	towerQueue.updateCond = sync.NewCond(&towerQueue.updateMtx)

	return towerQueue
}

func (t *TowerQueue) Start() error {
	if !atomic.CompareAndSwapUint32(&t.started, 0, 1) {
		return nil
	}

	go t.batchQueuer()

	return nil
}

func (t *TowerQueue) Stop() error {
	if !atomic.CompareAndSwapUint32(&t.stopped, 0, 1) {
		return nil
	}

	close(t.quit)

	return nil
}

func (t *TowerQueue) ForceQuit() error {
	if !atomic.CompareAndSwapUint32(&t.forced, 0, 1) {
		return nil
	}

	close(t.force)

	return nil
}

func (t *TowerQueue) Wait() {
	t.signalUntilShutdown()
}

type UpdateBatch struct {
	Tower   *wtdb.Tower
	Updates []*wtwire.StateUpdate
}

func (t *TowerQueue) batchQueuer() {
	defer close(t.shutdown)

	var finalPass bool
	for {
		t.updateCond.L.Lock()
		for t.updates.Front() == nil {
			t.updateCond.Wait()

			select {
			case <-t.force:
				t.updateCond.L.Unlock()
				return
			default:
			}

			select {
			case <-t.quit:
				if finalPass {
					t.updateCond.L.Unlock()
					return
				}
				finalPass = true
			default:
			}
		}
		t.updateCond.L.Unlock()

		// TODO(conner): randomize backkup interval
		select {
		case <-time.After(t.batchInterval):
		case <-t.quit:
		}

		var updates []*wtdb.RevokedState
		t.updateCond.L.Lock()
		for e := t.updates.Front(); e != nil; e = e.Next() {
			update := t.updates.Remove(e).(*wtwire.StateUpdate)
			updates = append(updates, update)
		}
		t.updateCond.L.Unlock()

		batch := &UpdateBatch{
			Tower:   t.tower,
			Updates: updates,
		}

		// Ensure delivery to peer?
		select {
		case t.batchReady <- batch:
		case <-t.force:
			return
		}

		select {
		case <-t.quit:
			if finalPass {
				return
			}
			finalPass = true
		default:
		}
	}
}

func (t *TowerQueue) signalUntilShutdown() {
	for {
		select {
		case <-time.After(time.Millisecond):
			t.updateCond.Signal()
		case <-t.shutdown:
			return
		}
	}
}

func (t *TowerQueue) QueueState(state *wtire.StateUpdate) error {
	select {
	case <-t.quit:
		return ErrTowerQueueShuttingDown
	default:
	}

	t.updateCond.L.Lock()
	t.updates.PushBack(state)
	t.updateCond.L.Unlock()

	t.updateCond.Signal()

	return nil
}

type revokedStateQueue struct {
	started uint32
	stopped uint32
	forced  uint32

	queueMtx  sync.Mutex
	queueCond *sync.Cond
	queue     *list.List

	newRevokedStates chan []*wtdb.RevokedState

	quit     chan struct{}
	force    chan struct{}
	shutdown chan struct{}
}

func newRevokedStateQueue() *revokedStateQueue {
	q := &revokedStateQueue{
		queue:            list.New(),
		newRevokedStates: make(chan []*wtdb.RevokedState),
		quit:             make(chan struct{}),
		force:            make(chan struct{}),
		shutdown:         make(chan struct{}),
	}
	q.queueCond = sync.NewCond(&q.queueMtx)

	return q
}

func (q revokedStateQueue) Start() error {
	if !atomic.CompareAndSwapUint32(&q.started, 0, 1) {
		return nil
	}

	go queueManager()

	return nil
}

func (q *revokedStateQueue) Stop() error {
	if !atomic.CompareAndSwapUint32(&q.stopped, 0, 1) {
		return nil
	}

	close(q.quit)

	return nil
}

func (q *revokedStateQueue) ForceQuit() error {
	if !atomic.CompareAndSwapUint32(&q.forced, 0, 1) {
		return nil
	}

	close(q.force)

	return nil
}

func (q *revokedStateQueue) Wait() {
	q.signalUntilShutdown()
}

func (q *revokedStateQueue) signalUntilShutdown() {
	for {
		select {
		case <-time.After(time.Millisecond):
			t.updateCond.Signal()
		case <-t.shutdown:
			return
		}
	}
}

func (q *revokedStateQueue) queueManager() {
	defer close(q.shutdown)

	var finalPass false
	for {
		q.queueCond.L.Lock()
		for q.queue.Front() == nil {
			q.queueCond.Wait()

			select {
			case <-q.force:
				q.queueCond.L.Unlock()
				return
			default:
			}

			select {
			case <-q.quit:
				if finalPass {
					q.queueCond.L.Unlock()
					return
				}
				finalPass = true
			default:
			}
		}

		var revokedStates []*wtdb.RevokedState
		for e := t.queue.Front(); e != nil; e = e.Next() {
			revokedState := t.queue.Remove(e).(*wtdb.RevokedState)
			revokedStates = append(revokedStates, revokedState)
		}
		q.queueCond.L.Unlock()

		select {
		case q.newRevokedStates <- revokedStates:
		case <-q.force:
			return
		}

		select {
		case <-q.quit:
			if finalPass {
				return
			}
			finalPass = true
		default:
		}
	}
}

func (q *revokedStateQueue) NewRevokedStates() <-chan []*wtdb.RevokedState {
	return q.newRevokedStates
}

func (q *revokedStates) QueueRevokedState(states ...*wtdb.RevokedState) error {
	q.queueCond.L.Lock()
	select {
	case <-q.quit:
		q.queueCond.L.Unlock()
		return ErrTowerQueueShuttingDown
	default:
	}

	for _, state := range states {
		q.queue.PushBack(state)
	}
	q.queueCond.L.Unlock()

	q.queueCond.Signal()

	return nil
}
