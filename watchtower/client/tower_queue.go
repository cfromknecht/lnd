package client

import (
	"container/list"
	"errors"
	"sync"
	"sync/atomic"
	"time"
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
	t.signalUntilShutdown()

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
	<-t.shutdown
}

type UpdateBatch struct {
	Tower   *wtdb.Tower
	Updates []*wtwire.StateUpdate
}

func (t *TowerQueue) batchQueuer() {
	defer close(t.shutdown)

	for {
		t.updateCond.L.Lock()
		for t.updates.Front() == nil {
			t.updateCond.Wait()

			select {
			case <-t.quit:
				t.updateCond.L.Unlock()
				return
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
		case batchReady <- batch:
		case <-t.force:
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
