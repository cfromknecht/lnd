package client

import "sync"

type updateManager struct {
	started uint32
	stopped uint32

	towerQueues []*TowerQueue

	wg   sync.WaitGroup
	quit chan struct{}
}

func (m *updateManager) Start() error {
	if !atomic.CompareAndSwapUint32(&m.started, 0, 1) {
		return nil
	}

	return nil
}

func (m *updateManager) Stop() error {
	if !atomic.CompareAndSwapUint32(&m.stopped, 0, 1) {
		return nil
	}

	close(m.quit)
	m.wg.Wait()

	return nil
}

type sessionPQ []*sessionState

func (pq sessionPQ) Len() int {
	return len(pq)
}

func (pq sessionPQ) Less(i, j int) bool {
	return pq[i].Score() > pq[j].Score()
}

func (pq sessionPQ) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *sessionPQ) Push(x interface{}) {
	item := x.(*ClientSessionInfo)
	*pq = append(*pq, item)
}

func (pq *sessionPQ) Pop() interface{} {
	n := len(*pq)
	item := (*pq)[n-1]
	*pq = (*pq)[0 : n-1]
	return item
}
