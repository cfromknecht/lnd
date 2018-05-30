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

type TowerPriorityQueue []*ClientSessionInfo

func (pq TowerPriorityQueue) Len() int {
	return len(pq)
}

func (pq TowerPriorityQueue) Less(i, j int) bool {
	return pq[i].LastSeqNum > pq[j].LastSeqNum
}

func (pq TowerPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *TowerPriorityQueue) Push(x interface{}) {
	item := x.(*ClientSessionInfo)
	*pq = append(*pq, item)
}

func (pq *TowerPriorityQueue) Pop() interface{} {
	n := len(*pq)
	item := (*pq)[n-1]
	*pq = (*pq)[0 : n-1]
	return item
}
