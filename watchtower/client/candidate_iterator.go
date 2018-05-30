package client

type TowerCandidateIterator interface {
	Next() (*towerConfig, error)
}

// TODO(conner): implement db backed candidate iterator
type towerListIterator struct {
	curCandidate int
	candidates   []*towerListIterator
}

func NewTowerListIterator(candidates []*towerConfig) *towerListIterator {
	return &towerListIterator{
		candidates: candidates,
	}
}

var ErrTowerCandidatesExhausted = errors.New("unable to find enough watchtowers")

func (t *towerListIterator) Next() (*towerConfig, error) {
	if t.curCandidate >= len(t.candidates) {
		return nil, ErrTowerCandidatesExhausted
	}

	tower := t.candidates[t.curCandidate]
	t.curCandidate++

	return tower, nil
}
