package wtclient

import (
	"container/list"
	"sync"

	"github.com/lightningnetwork/lnd/lnwire"
)

type TowerCandidateIterator interface {
	Next() (*lnwire.NetAddress, error)
	Reset() error
}

// TODO(conner): implement db backed candidate iterator
type towerListIterator struct {
	mu            sync.Mutex
	candidates    *list.List
	nextCandidate *list.Element
}

func NewTowerListIterator(candidates ...*lnwire.NetAddress) *towerListIterator {
	iter := &towerListIterator{
		candidates: list.New(),
	}

	for _, candidate := range candidates {
		iter.candidates.PushBack(candidate)
	}
	iter.nextCandidate = iter.candidates.Front()

	return iter
}

func (t *towerListIterator) Next() (*lnwire.NetAddress, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.nextCandidate == nil {
		return nil, ErrTowerCandidatesExhausted
	}

	tower := t.nextCandidate.Value.(*lnwire.NetAddress)
	t.nextCandidate = t.nextCandidate.Next()

	return tower, nil
}

func (t *towerListIterator) Reset() error {
	t.nextCandidate = t.candidates.Front()
	return nil
}
