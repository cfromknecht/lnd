package client

import (
	"container/list"
	"errors"
	"sync"

	"github.com/lightningnetwork/lnd/lnwire"
)

type TowerCandidateIterator interface {
	Next() (*lnwire.NetAddress, error)
}

// TODO(conner): implement db backed candidate iterator
type towerListIterator struct {
	mu           sync.Mutex
	curCandidate int
	candidates   *list.List
}

func NewTowerListIterator(candidates []*lnwire.NetAddress) *towerListIterator {
	iter := &towerListIterator{
		candidates: list.New(),
	}

	for _, candidate := range candidates {
		iter.candidates.PushBack(candidate)
	}

	return iter
}

var ErrTowerCandidatesExhausted = errors.New("unable to find enough watchtowers")

func (t *towerListIterator) Next() (*lnwire.NetAddress, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	next := t.candidates.Front()
	if next == nil {
		return nil, ErrTowerCandidatesExhausted
	}

	tower := t.candidates.Remove(next).(*lnwire.NetAddress)
	t.curCandidate++

	return tower, nil
}
