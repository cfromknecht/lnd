package client

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/watchtower/sweep"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/lightningnetwork/lnd/watchtower/wtwire"
)

type ReserveLevel byte

const (
	ReserveLevelInvalid ReserveLevel = iota
	ReserveLevelCritical
	ReserveLevelLow
	ReserveLevelGucci
)

func (e ReserveLevel) String() string {
	switch e {
	case ReserveLevelInvalid:
		return "ReserveLevelInvalid"
	case ReserveLevelCritical:
		return "ReserveLevelCritical"
	case ReserveLevelLow:
		return "ReserveLevelLow"
	case ReserveLevelGucci:
		return "ReserveLevelGucci"
	default:
		return "UnknownReserveLevel"
	}
}

type ReserveManager interface {
	AddSession(*sessionState) error
	QueueState(state *RevokedState) error
}

// TODO(conner): make persistent
type reserveManager struct {
	started uint32
	stopped uint32

	numBackups int
	negotiator SessionNegotiator

	reserveState ReserveLevel

	queue    *revokedStateQueue
	sessions map[*wtdb.SessionID]*sessionState

	wg   sync.WaitGroup
	quit chan struct{}
}

func newReserveManager(
	negotiator SessionNegotiator,
	numBackups int) *reserveManager {

	return &reserveManager{
		numBackups: numBackups,
		negotiator: negotiator,
		queue:      newRevokedStateQueue(),
		sessions:   make(map[*lnwire.NetAddress]*ClientSessionInfo),
		quit:       make(chan struct{}),
	}
}

func (s *reserveManager) Start() error {
	if !atomic.CompareAndSwapUint32(&s.started, 0, 1) {
		return nil
	}

	return s.loadInitialState()
}

func (s *reserveManager) Stop() error {
	if !atomic.CompareAndSwapUint32(&s.started, 0, 1) {
		return nil
	}

	close(s.quit)
	w.wg.Wait()

	return nil
}

func (m *reserveManager) AddSession(session *sessionState) error {
	sessionID := session.ID()

	if _, ok := m.sessions[sessionID]; ok {
		return ErrSessionAlreadyActive
	}

	m.sessions[sessionID] = session

	return nil
}

var (
	ErrSessionsExhausted    = errors.New("unable to find available session")
	ErrSessionExhausted     = errors.New("session has exhausted all updates")
	ErrSessionFull          = errors.New("unable to queue update, all updates reserved")
	ErrLowSession           = errors.New("unable session detected as low")
	ErrSessionAlreadyActive = errors.New("session already active")
)

func (m *reserveManager) QueueState(state *wtwire.StateUpdate) error {
	var numScheduledBackups int
	var haveLowSession bool
	for id, session := range m.sessions {
		err := session.QueueState(state)
		switch {

		case err == ErrSessionExhausted:
			delete(m.sessions, id)

		case err == ErrSessionFull:
			continue

		case err == ErrLowSession:
			haveLowSession = true
			numScheduledBackups++

		case err != nil:
			return err

		default:
			numScheduledBackups++
		}

		if numScheduledBackups == m.numBackups {
			break
		}
	}

	if numScheduledBackups < m.numScheduledBackups {
		// TODO(conner): schedule remaining
		return ErrSessionsExhausted
	}
	if haveLowSession {
		return ErrLowSession
	}

	return nil
}

type sessionState struct {
	mu sync.Mutex

	tower *wtdb.Tower
	info  *wtdb.SessionInfo

	queue      *TowerQueue
	numPending uint16
}

func (s *sessionState) ID() wtdb.SessionID {
	return wtdb.NewSessionIDFromPubKey(s.tower.IdentityKey)
}

const defaultInterval = 1 * time.Second

func newSessionState(tower *wtdb.Tower, info *wtdb.SessionInfo) *sessionState {
	queue := NewTowerQueue(tower, defaultInterval, network)
	return &sessionState{
		tower: tower,
		info:  info,
		queue: queue,
	}
}

func (s *sessionState) updatesRemaining() uint16 {
	return s.info.MaxUpdates - s.info.SeqNum - s.numPending
}

func (s *sessionState) percentUsed() float64 {
	return float64(s.info.SeqNum+s.numPending) / float64(s.info.MaxUpdates)
}

func (s *sessionState) Score() float64 {
	// TODO(conner): factor reliability, ping, etc
	return s.percentUsed()
}

func (s *sessionState) QueueState(state *wtwire.StateUpdate) error {
	if s.updatesRemaining() == 0 {
		if s.Exhausted() {
			return ErrSessionExhausted
		}
		return ErrSessionFull
	}

	err := s.queue.QueueState(state)
	if err != nil {
		return err
	}

	s.numPending++

	const lowThreshold = float64(0.2)
	used := float64(s.info.LastSeqNum+s.numPending) / float64(s.MaxUpdates)
	if used+lowThreshold >= 1.0 {
		return ErrLowSession
	}

	return nil
}

func (s *sessionState) Exhausted() bool {
	return s.info.LastSeqNum == s.info.MaxUpdates
}

type ClientSessionInfo struct {
	Addr        *lnwire.NetAddress
	SessionInfo *wtdb.SessionInfo
}

func (s *reserveManager) reserveManager() {
	defer s.wg.Done()

	var exitErr error
	for {
		var (
			nextState ReserveLevel
			err       error
		)

		switch s.reserveState {
		case ReserveLevelCritical:
			nextState, err = criticalManager()
		case ReserveLevelLow:
			nextState, err = lowManager()
		case ReserveLevelGucci:
			nextState, err = gucciManager()
		default:
			err = fmt.Errorf("unknown reserve state=%s",
				s.reserveState)
		}

		if err != nil {
			exitErr = err
			return
		}

		err = s.verifyTransition(nextState)
		if err != nil {
			exitErr = err
			return
		}

		s.reserveState = nextState
	}
}

type ErrInvalidTransition struct {
	from ReserveLevel
	to   ReserveLevel
}

func (e ErrInvalidTransition) Error() string {
	return fmt.Errorf("invalid transition from reserve level %s to "+
		"%s", e.from, e.to)
}

func (s *reserveManager) verifyTransition(nextState ReserveLevel) error {
	trxnErr := ErrInvalidTransition{s.reserveState, nextState}
	if nextState == ReserveLevelInvalid {
		return trxnErr
	}

	switch s.reserveState {
	case ReserveLevelGucci:
		switch nextState {
		case ReserveLevelLow:
			return nil
		default:
			return trxnErr
		}

	case ReserveLevelLow:
		switch nextState {
		case ReserveLevelGucci:
			return nil
		case ReserveLevelCritical:
			return nil
		default:
			return trxnErr
		}

	case ReserveLevelCritical:
		switch nextState {
		case ReserveLevelGucci:
			return nil
		default:
			return trxnErr
		}

	default:
		return trxnErr
	}
}

func (s *reserveManager) criticalManager() (ReserveLevel, error) {
	s.negotiator.RequestSession()

	for {
		select {
		case sessionInfo := <-s.negotiator.NewSessions():
			// TODO(conner): write info to client session db
			err := s.AddSession(sessionInfo)
			if err != nil {
				return ReserveLevelInvalid, err
			}

		case <-c.quit:
			return ReserveLevelInvalid, ErrWtClientShuttingDown
		}

		if !s.isLow() {
			return ReserveLevelGucci, nil
		}

		s.negotiator.RequestSession()
	}
}

func (s *reserveManager) lowManager() (ReserveLevel, error) {
	s.negotiator.RequestSession()

	for {
		var (
			decreasesReserve bool
			increasesReserve bool
		)

		select {
		case sessionInfo := <-s.negotiator.NewSessions():
			err := s.AddSession(sessionInfo)
			if err != nil {
				return ReserveLevelInvalid, err
			}
			increasesReserve = true

		case update := <-s.queue.NewRevokedStates():
			err := s.QueueState(update)
			switch {
			case err == ErrLowSession:
			case err == ErrSessionsExhausted:
				decreasesReserve = true
			case err != nil:
				return ReserveLevelInvalid, err
			}

		case <-s.quit:
			return ReserveLevelInvalid, ErrWtClientShuttingDown
		}

		if decreasesReserve && s.isCritical() {
			return ReserveLevelCritical, nil
		}
		if increasesReserve {
			if !s.isLow() {
				return ReserveLevelGucci, nil
			}
			s.negotiator.RequestSession()
		}
	}
}

func (s *reserveManager) gucciManager() (ReserveLevel, error) {
	for {
		var decreasesReserve bool
		select {
		case sessionInfo := <-s.negotiator.NewSessions():
			err := s.AddSession(sessionInfo)
			if err != nil {
				return ReserveLevelInvalid, err
			}

		case revokedStates := <-s.queue.NewRevokedStates():
			err := s.QueueState(revokedStates)
			// TODO(conner): add err for low
			switch {
			case err == ErrLowSession:
				decreasesReserve = true
			case err != nil:
				return ReserveLevelInvalid, err
			}

		case <-s.quit:
			return ReserveLevelInvalid, ErrWtClientShuttingDown
		}

		if decreasesReserve && s.isLow() {
			return ReserveLevelLow, nil
		}
	}
}

func (s *reserveManager) isCritical() bool {
	var numReplicas int
	for _, session := range s.sessions {
		if session.reserveState == ReserveLevelGucci ||
			session.reserveState == ReserveLevelLow {
			numReplicas++
		}
	}

	return numReplicas < s.numTowers
}

func (s *reserveManager) isLow() bool {
	var numGucci int
	for _, session := range s.sessions {
		if session.reserveState == ReserveLevelGucci {
			numGucci++
		}
	}

	return numGucci < s.numTowers
}
