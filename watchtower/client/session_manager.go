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
	ReserveLevelEmpty
	ReserveLevelCritical
	ReserveLevelLow
	ReserveLevelGucci
)

func (e ReserveLevel) String() string {
	switch e {
	case ReserveLevelInvalid:
		return "ReserveLevelInvalid"
	case ReserveLevelEmpty:
		return "ReserveLevelEmpty"
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

type SessionManager interface {
	AddSession(*sessionState) error
	QueueState(state *RevokedState) error
}

// TODO(conner): make persistent
type sessionManager struct {
	started uint32
	stopped uint32

	numBackups int

	mu           sync.Mutex
	sessions     map[*wtdb.SessionID]*sessionState
	reserveState ReserveLevel

	wg   sync.WaitGroup
	quit chan struct{}
}

func newSessionManager() *sessionManager {
	return &sessionManager{
		sessions: make(map[*lnwire.NetAddress]*ClientSessionInfo),
		quit:     make(chan struct{}),
	}
}

func (s *sessionManager) Start() error {
	if !atomic.CompareAndSwapUint32(&s.started, 0, 1) {
		return nil
	}

	return s.loadInitialState()
}

func (s *sessionManager) Stop() error {
	if !atomic.CompareAndSwapUint32(&s.started, 0, 1) {
		return nil
	}

	close(s.quit)
	w.wg.Wait()

	return nil
}

func (m *sessionManager) AddSession(session *sessionState) error {
	sessionID := session.ID()

	m.mu.Lock()
	if _, ok := m.sessions[sessionID]; ok {
		m.mu.Unlock()
		return ErrSessionAlreadyActive
	}
	m.sessions[session.ID()] = session
	m.mu.Unlock()

	return nil
}

var (
	ErrSessionsExhausted    = errors.New("unable to find available session")
	ErrSessionExhausted     = errors.New("session has exhausted all updates")
	ErrSessionFull          = errors.New("unable to queue update, all updates reserved")
	ErrSessionAlreadyActive = errors.New("session already active")
)

func (m *sessionManager) QueueState(state *wtwire.StateUpdate) error {
	var numScheduledBackups int
	m.mu.Lock()
	for id, session := range m.sessions {
		err := session.QueueState(state)
		switch {

		case err == ErrSessionExhausted:
			delete(m.sessions, id)

		case err == ErrSessionFull:
			continue

		case err != nil:
			m.mu.Unlock()
			return err

		default:
			numScheduledBackups++
		}

		if numScheduledBackups == m.numBackups {
			break
		}
	}
	m.mu.Unlock()

	if numScheduledBackups < m.numScheduledBackups {
		// TODO(conner): schedule remaining
		return ErrSessionsExhausted
	}

	return nil
}

func (c *Client) initSessions(numTowers int) error {
	if numTowers == 0 {
		return nil
	}

	// TODO(conner): check num active sessions

	twrs, err := c.fetchTowers(numTowers)
	if err != nil {
		return err
	}

	candidates := NewTowerListIterator(twrs)

	dispatcher := make(chan struct{}, numTowers)
	for i := 0; i < numTowers; i++ {
		dispatcher <- struct{}{}
	}

	sessions := make(chan struct{})

	var numComplete int
	for {
		select {
		case <-dispatcher:
			tower, err := candidates.Next()
			if err != nil {
				return err
			}

			c.wg.Add(1)
			go c.initSession(tower, dispatcher, sessions)

		case sessionInfo := <-sessions:
			// TODO(conner): write info to client session db
			err := c.sessions.AddSession(sessionInfo)
			if err != nil {
				return err
			}

			numComplete++
			if numComplete >= numTowers {
				return nil
			}

		case <-c.quit:
			return ErrWtClientShuttingDown
		}
	}
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

	return nil
}

func (s *sessionState) Exhausted() bool {
	return s.info.LastSeqNum == s.info.MaxUpdates
}

type ClientSessionInfo struct {
	Addr        *lnwire.NetAddress
	SessionInfo *wtdb.SessionInfo
}

func (c *Client) initSession(tower *towerConfig, dispatcher chan struct{},
	sessions chan *sessionState) {

	defer c.wg.Done()

	var needRetry = true
	defer func() {
		if needRetry {
			select {
			case dispatcher <- struct{}{}:
			case <-quit:
			}
		}
	}()

	conn, err := c.connect(tower)
	if err != nil {
		fmt.Printf("unable to connect to watchtower=%v: %v\n",
			tower.addr, err)
		return
	}

	// TODO(conner): add tower to known peers after successful connection

	init := &wtwire.SessionInit{
		Version:      sweep.BlobVersion0,
		MaxUpdates:   c.cfg.UpdatesPerSession,
		RewardRate:   c.cfg.RewardRate,
		SweepFeeRate: c.cfg.SweepFeeRate,
	}

	sessionID := wtdb.NewSessionIDFromPubKey(c.identityPriv.PubKey())

	// TODO(conner): set sweep address

	info := &wtdb.SessionInfo{
		ID:           sessionID,
		Version:      sweep.BlobVersion0,
		MaxUpdates:   c.cfg.UpdatesPerSession,
		RewardRate:   c.cfg.RewardRate,
		SweepFeeRate: c.cfg.SweepFeeRate,
	}

	// Send SessionInit message.
	err = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if err != nil {
		fmt.Printf("unable to set write deadline: %v\n", err)
		return
	}

	err = sendMessage(conn, init)
	if err != nil {
		fmt.Printf("unable to send init message to watchtower=%v: %v\n",
			tower.addr, err)
		return
	}

	// Receive SessionAccept/SessionReject message.
	err = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err != nil {
		fmt.Printf("unable to set read deadline: %v\n", err)
		return
	}

	// Wait for response.
	rawMsg, err := conn.ReadNextMessage()
	if err != nil {
		return

	}

	msgReader := bytes.NewReader(rawMsg)
	msg, err := wtwire.ReadMessage(msgReader, 0)
	if err != nil {
		return
	}

	switch resp := msg.(type) {
	case *wtwire.SessionAccept:
		info.RewardAddress = resp.RewardAddress

		needRetry = false

		// TODO(conner): write session

		select {
		case sessions <- &ClientSessionInfo{
			Addr:        tower.addr,
			SessionInfo: info,
		}:
		case <-quit:
		}

	case *wtwire.SessionReject:

	default:
		fmt.Printf("received malformed response to session init")
	}
}

func (s *sessionManager) stateManager() {
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
			err = fmt.Errorf("unknown reserve state")
		}

		if err != nil {
			exitErr = err
			return
		}

		err = s.makeTransition(nextState)
		if err != nil {
			exitErr = err
			return
		}
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

func (s *sessionManager) makeTransition(nextState ReserveLevel) error {
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

func (s *sessionManager) criticalManager() (ReserveLevel, error) {
	// TODO(conner): check num active sessions

	numTowers := s.numTowersTillGucci()
	if numTowers == 0 {
		return nil
	}

	twrs, err := c.fetchTowers(numTowers)
	if err != nil {
		return err
	}

	candidates := NewTowerListIterator(twrs)

	dispatcher := make(chan struct{}, numTowers)
	for i := 0; i < numTowers; i++ {
		dispatcher <- struct{}{}
	}

	sessions := make(chan struct{})

	var numComplete int
	for {
		select {
		case update := <-s.newUpdates:
			// TODO(conner): add to overflow queue

		case <-dispatcher:
			tower, err := candidates.Next()
			if err != nil {
				// TODO(conner): wait for pending session to
				// clean up?
				return ReserveLevelInvalid, err
			}

			c.wg.Add(1)
			go s.initSession(tower, dispatcher, sessions)

		case sessionInfo := <-sessions:
			// TODO(conner): write info to client session db
			err := s.AddSession(sessionInfo)
			if err != nil {
				return err
			}

			numComplete++
			if numComplete >= numTowers {
				return ReserveLevelGucci, nil
			}

		case <-c.quit:
			return ReserveLevelInvalid, ErrWtClientShuttingDown
		}
	}
}

func (s *sessionManager) lowManager() (ReserveLevel, error) {
	defer s.wg.Done()

	for {
		var decreasesReserve bool
		var increasesReserve bool
		select {
		case sessionInfo := <-sessions:
			err := s.AddSession(sessionInfo)
			if err != nil {
				return ReserveLevelInvalid, err
			}
			increasesReserve = true

		case update := <-s.newUpdates:
			err := s.QueueState(update)
			switch {
			// TODO(conner): add err for low
			case err == ErrSessionsExhausted:
				s.pruneEmptySessions()
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
		if increasesReserve && !s.isLow() {
			return ReserveLevelGucci, nil
		}
	}
}

func (s *sessionManager) gucciManager() (ReserveLevel, error) {
	defer s.wg.Done()

	for {
		select {
		case update := <-s.newUpdates:
			err := s.QueueState(update)
			if err != nil {
				return ReserveLevelInvalid, err
			}

		case <-s.quit:
			return ReserveLevelInvalid, ErrWtClientShuttingDown
		}

		if s.isLow() {
			return ReserveLevelLow, nil
		}
	}
}

func (s *sessionManager) isCritical() bool {
	var numReplicas int
	for _, session := range s.sessions {
		if session.reserveState == ReserveLevelGucci ||
			session.reserveState == ReserveLevelLow {
			numReplicas++
		}
	}

	return numReplicas < s.numTowers
}

func (s *sessionManager) isLow() bool {
	var numGucci int
	for _, session := range s.sessions {
		if session.reserveState == ReserveLevelGucci {
			numGucci++
		}
	}

	return numGucci < s.numTowers
}

func (s *sessionManager) pruneEmptySessions() {
	for id, session := range s.sessions {
		if session.reserveState == ReserveLevelEmpty {
			delete(s.sessions, id)
		}
	}
}
