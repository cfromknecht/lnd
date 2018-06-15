package client

import (
	"container/list"
	"errors"
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

var ErrTowerCandidatesExhausted = errors.New("unable to find enough watchtowers")

func (t *towerListIterator) Next() (*lnwire.NetAddress, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if iter.nextCandidate == nil {
		return nil, ErrTowerCandidatesExhausted
	}

	tower := iter.nextCandidate(*lnwire.NetAddress)
	iter.nextCandidate = iter.nextCandidate.Next()

	return tower, nil
}

func (t *towerListIterator) Reset() error {
	t.nextCandidate = t.candidates.Front()
	return nil
}
