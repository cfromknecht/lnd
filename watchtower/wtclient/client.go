package wtclient

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tor"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/lightningnetwork/lnd/watchtower/wtpolicy"
	"github.com/lightningnetwork/lnd/watchtower/wtserver"
	"github.com/lightningnetwork/lnd/watchtower/wtwire"
)

const (
	DefaultTowerPort = 9911

	DefaultReadTimeout = 15 * time.Second

	DefaultWriteTimeout = 15 * time.Second

	DefaultStatInterval = 30 * time.Second
)

type Client interface {
	// Start initializes the watchtower client, allowing it process requests
	// to backup revoked channel states.
	Start() error

	// BackupState initiates a request to back up a particular revoked
	// state. If the method returns nil, the backup is guaranteed to be
	// successful unless the client is force quit, or the justice
	// transaction would create dust outputs when trying to abide by the
	// negotiated policy.
	BackupState(*lnwire.ChannelID, *lnwallet.BreachRetribution) error

	// Stop attempts a graceful shutdown of the watchtower client. In doing
	// so, it will attempt to flush the pipeline and deliver any queued
	// states to the tower before exiting.
	Stop() error

	// ForceQuit will forcibly shutdown the watchtower client. Calling this
	// may lead to queued states being dropped.
	ForceQuit()
}

type Config struct {
	// Signer
	Signer lnwallet.Signer

	NewAddress func() ([]byte, error)

	SecretKeyRing keychain.SecretKeyRing

	NetDial NetDialer

	DB DB

	Net tor.Net

	Policy wtpolicy.Policy

	PrivateTower *lnwire.NetAddress

	WriteTimeout time.Duration

	ReadTimeout time.Duration

	ForceQuitDelay time.Duration
}

type TowerClient struct {
	started uint32 // to be used atomically
	stopped uint32 // to be used atomically
	forced  uint32 // to be used atomically
	logged  uint32 // to be used atomically

	cfg *Config

	pipeline *taskPipeline

	negotiator        SessionNegotiator
	candidateSessions map[wtdb.SessionID]*wtdb.ClientSessionInfo
	activeSessions    SessionQueueSet

	sessionQueue *SessionQueue
	prevTask     *backupTask

	sweepAddr []byte

	statTicker *time.Ticker
	stats      clientStats

	wg sync.WaitGroup
}

func New(config *Config) (*TowerClient, error) {
	// Copy the config to prevent side-effects from modifying both the
	// internal and external version of the Config.
	cfg := new(Config)
	*cfg = *config

	if cfg.Net == nil {
		return nil, ErrNoNetwork
	}

	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = DefaultReadTimeout
	}

	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = DefaultWriteTimeout
	}

	sweepAddr, err := cfg.NewAddress()
	if err != nil {
		log.Errorf("Unable to generate new sweep addr: %v", err)
	}

	tower, err := cfg.DB.CreateTower(cfg.PrivateTower)
	if err != nil {
		return nil, err
	}

	log.Infof("Using private watchtower %x@%s with offering policy %s",
		cfg.PrivateTower.IdentityKey.SerializeCompressed(),
		cfg.PrivateTower.Address, cfg.Policy)

	candidates := NewTowerListIterator(tower.ToLNAddrs()...)

	c := &TowerClient{
		cfg:               cfg,
		pipeline:          newTaskPipeline(),
		candidateSessions: make(map[wtdb.SessionID]*wtdb.ClientSessionInfo),
		activeSessions:    make(SessionQueueSet),
		sweepAddr:         sweepAddr,
		statTicker:        time.NewTicker(DefaultStatInterval),
	}
	c.negotiator = NewSessionNegotiator(&NegotiatorConfig{
		DB:          cfg.DB,
		Policy:      cfg.Policy,
		SendMessage: c.sendMessage,
		ReadMessage: c.readMessage,
		Dial:        c.dial,
		Candidates:  candidates,
	})

	return c, nil
}

// Start initializes the watchtower client by loading or negotiating an active
// session and then begins processing backup tasks from the request pipeline.
func (c *TowerClient) Start() error {
	if !atomic.CompareAndSwapUint32(&c.started, 0, 1) {
		return nil
	}

	log.Infof("Starting watchtower client")

	err := c.negotiator.Start()
	if err != nil {
		return err
	}

	c.candidateSessions, err = c.cfg.DB.ListActiveSessions()
	if err != nil {
		return err
	}

	c.pipeline.Start()

	c.wg.Add(1)
	go c.backupDispatcher()

	log.Infof("Watchtower client started successfully")

	return nil
}

// Stop idempotently initiates a graceful shutdown of the watchtower client.
func (c *TowerClient) Stop() error {
	if !atomic.CompareAndSwapUint32(&c.stopped, 0, 1) {
		return nil
	}

	log.Infof("Stopping watchtower client")

	// 1. Shutdown the backup queue, which will prevent any further updates
	// from being accepted. In practice, the links should be shutdown before
	// the client has been stopped, so all updates would have been added
	// prior.
	c.pipeline.Stop()

	// 2. To ensure we don't hang forever on shutdown due to unintended
	// failures, we'll delay a call to force quit the pipeline if a
	// ForceQuitDelay is specified. This will have no effect if the pipeline
	// shuts down cleanly before the delay fires.
	//
	// For full safety, this can be set to 0 and wait out indefinitely.
	// However for mobile clients which may have a limited amount of time to
	// exit before the background process is killed, this offers a way to
	// ensure the process terminates.
	if c.cfg.ForceQuitDelay > 0 {
		time.AfterFunc(c.cfg.ForceQuitDelay, c.ForceQuit)
	}

	// 3. Once the backup queue has shutdown, wait for the main dispatcher
	// to exit. The backup queue will signal it's completion to the
	// dispatcher, which releases the wait group after all tasks have been
	// assigned to session queues.
	c.wg.Wait()

	// 4. Since all valid tasks have been assigned to session queues, we no
	// longer need to negotiate sessions.
	c.negotiator.Stop()

	log.Infof("Waiting for active session queues to finish draining, "+
		"stats: %s", c.stats)

	// 5. Shutdown all active session queues in parallel. These will exit
	// once all updates have been acked by the watchtower.
	c.activeSessions.ApplyAndWait(func(s *SessionQueue) func() {
		return s.Stop
	})

	if atomic.CompareAndSwapUint32(&c.logged, 0, 1) {
		log.Infof("Client successfully stopped, stats: %s", c.stats)
	}

	return nil
}

func (c *TowerClient) ForceQuit() {
	if !atomic.CompareAndSwapUint32(&c.forced, 0, 1) {
		return
	}

	log.Infof("Force quitting watchtower client")

	// 1. Shutdown the backup queue, which will prevent any further updates
	// from being accepted. In practice, the links should be shutdown before
	// the client has been stopped, so all updates would have been added
	// prior.
	c.pipeline.ForceQuit()

	// 2. Once the backup queue has shutdown, wait for the main dispatcher
	// to exit. The backup queue will signal it's completion to the
	// dispatcher, which releases the wait group after all tasks have been
	// assigned to session queues.
	c.wg.Wait()

	// 3. Since all valid tasks have been assigned to session queues, we no
	// longer need to negotiate sessions.
	c.negotiator.Stop()

	// 4. Force quit all active session queues in parallel. These will exit
	// once all updates have been acked by the watchtower.
	c.activeSessions.ApplyAndWait(func(s *SessionQueue) func() {
		return s.ForceQuit
	})

	if atomic.CompareAndSwapUint32(&c.logged, 0, 1) {
		log.Infof("Client successfully stopped, stats: %s", c.stats)
	}
}

func (c *TowerClient) nextSessionQueue() *SessionQueue {
	if len(c.candidateSessions) == 0 {
		return nil
	}

	/*
		sweepAddr, err := c.cfg.NewAddress()
		if err != nil {
			log.Errorf("Unable to generate new sweep addr, "+
				"reusing previous sweep address: %v", err)
			sweepAddr = c.lastSweepAddr
		} else {
			// If successful, record the last sweep address. This allows the client
			// to continue backing up during shutdown if the backend shuts down and
			// we cannot create new addresses.
			c.lastSweepAddr = sweepAddr
		}
	*/

	// Select any candidate session at random, and remove it from the set of
	// candidate sessions.
	var candidateSession *wtdb.ClientSessionInfo
	for id, sessionInfo := range c.candidateSessions {
		delete(c.candidateSessions, id)

		// Skip any sessions with policies that don't match the current
		// configuration. These can be used again if the client changes
		// their configuration back.
		if sessionInfo.Policy != c.cfg.Policy {
			continue
		}

		candidateSession = sessionInfo
		break
	}

	// If none of the sessions could be used, we'll exit and signal that we
	// need another session to be negotiated.
	if candidateSession == nil {
		return nil
	}

	// Initialize the session queue and spin it up so it can begin handling
	// updates.
	sessionQueue := newSessionQueue(&SessionQueueConfig{
		ClientSession: candidateSession,
		SweepAddress:  c.sweepAddr,
		Dial:          c.dial,
		ReadMessage:   c.readMessage,
		SendMessage:   c.sendMessage,
		Signer:        c.cfg.Signer,
		DB:            c.cfg.DB,
	})

	// Add the session queue as an active session so that we remember to
	// stop it on shutdown.
	c.activeSessions.Add(sessionQueue)

	// Finally, start the queue so that it can be active in processing
	// assigned tasks.
	sessionQueue.Start()

	return sessionQueue
}

func (c *TowerClient) BackupState(chanID *lnwire.ChannelID,
	breachInfo *lnwallet.BreachRetribution) error {

	task := newBackupTask(chanID, breachInfo)

	return c.pipeline.QueueBackupTask(task)
}

// backupDispatcher processes events coming from the taskPipeline and is
// responsible for detecting when the client needs to renegotiate a session to
// fulfill continuing demand. The event loop exits after all tasks have been
// received from the upstream taskPipeline, or the taskPipeline is force quit.
//
// NOTE: This method MUST be run as a goroutine.
func (c *TowerClient) backupDispatcher() {
	defer c.wg.Done()

	log.Tracef("Starting backup dispatcher")
	defer log.Tracef("Stopping backup dispatcher")

	for {
		switch {

		// No active session queue and no additional sessions.
		case c.sessionQueue == nil && len(c.candidateSessions) == 0:
			log.Infof("Requesting new session.")

			// Immediately request a new session.
			c.negotiator.RequestSession()

			// Wait until we receive the newly negotiated session.
			// All backups sent in the meantime are queued in the
			// revoke queue, as we cannot process them.
			select {
			case session := <-c.negotiator.NewSessions():
				log.Infof("Acquired new session with id=%s",
					session.ID)
				c.candidateSessions[session.ID] = session
				c.stats.sessionAcquired()

			case <-c.statTicker.C:
				log.Infof("Client stats: %s", c.stats)
			}

		// No active session queue but have additional sessions.
		case c.sessionQueue == nil && len(c.candidateSessions) > 0:
			// We've exhausted the prior session, we'll pop another
			// from the remaining sessions and continue processing
			// backup tasks.
			c.sessionQueue = c.nextSessionQueue()

			log.Debugf("Loaded next candidate session queue id=%s",
				c.sessionQueue.ID())

		// Have active session queue, process backups.
		case c.sessionQueue != nil:
			if c.prevTask != nil {
				c.processTask(c.prevTask)

				// Continue to ensure the sessionQueue is
				// properly initialized before attempting to
				// process more tasks from the pipeline.
				continue
			}

			// Normal operation where new tasks are read from the
			// pipeline.
			select {

			// If any sessions are negotiated while we have an
			// active session queue, queue them for future use.
			case session := <-c.negotiator.NewSessions():
				log.Infof("Acquired new session with id=%s",
					session.ID)
				c.candidateSessions[session.ID] = session
				c.stats.sessionAcquired()

			case <-c.statTicker.C:
				log.Infof("Client stats: %s", c.stats)

			// Process each backup task serially from the queue of
			// revoked states.
			case task, ok := <-c.pipeline.NewBackupTasks():
				// All backups in the pipeline have been
				// processed, it is now safe to exit.
				if !ok {
					return
				}

				log.Debugf("Processing backup task chanid=%s "+
					"commit-height=%d", task.chanID,
					task.commitHeight)

				c.stats.taskReceived()
				c.processTask(task)
			}
		}
	}
}

// processTask attempts to schedule the given backupTask on the active
// sessionQueue. The task will either be accepted or rejected, afterwhich the
// appropriate modifications to the client's state machine will be made. After
// every invocation of processTask, the caller should ensure that the
// sessionQueue hasn't been exhausted before proceeding to the next task. Tasks
// that are rejected because the active sessionQueue is full will be cached as
// the prevTask, and should be reprocessed after obtaining a new sessionQueue.
func (c *TowerClient) processTask(task *backupTask) {
	status, accepted := c.sessionQueue.AcceptTask(task)
	if accepted {
		c.taskAccepted(task, status)
	} else {
		c.taskRejected(task, status)
	}
}

// taskAccepted processes the acceptance of a task by a sessionQueue depending
// on the state the sessionQueue is in *after* the task is added. The client's
// prevTask is always removed as a result of this call. The client's
// sessionQueue will be removed if accepting the task left the sessionQueue in
// an exhausted state.
func (c *TowerClient) taskAccepted(task *backupTask, newStatus ReserveStatus) {

	c.stats.taskAccepted()

	log.Debugf("Backup chanid=%s commit-height=%d accepted successfully",
		task.chanID, task.commitHeight)

	// If this task was accepted, we discard anything held in the prevTask.
	// Either it was nil before, or is the task which was just accepted.
	c.prevTask = nil

	switch newStatus {
	case ReserveAvailable:
		// The sessionQueue still has capacity after accepting this
		// task.

	case ReserveExhausted:
		c.stats.sessionExhausted()

		log.Debugf("Session %s exhausted", c.sessionQueue.ID())

		// This task left the session exhausted, set it to nil and
		// proceed to the next loop so we can consume another
		// pre-negotiated session or request another.
		c.sessionQueue = nil
	}
}

// taskRejected process the rejection of a task by a sessionQueue depending on
// the state the was in *before* the task was rejected. The client's prevTask
// will cache the task if the sessionQueue was exhausted before hand, and nil
// the sessionQueue to find a new session. If the sessionQueue was not
// exhausted, the client marks the task as ineligible, as this implies we
// couldn't construct a valid justice transaction given the session's policy.
func (c *TowerClient) taskRejected(task *backupTask, curStatus ReserveStatus) {

	switch curStatus {
	case ReserveAvailable:
		c.stats.taskIneligible()

		// TODO(conner): cannot back up
		log.Debugf("Backup chanid=%s commit-height=%d is ineligible")

		err := c.cfg.DB.MarkBackupIneligible(
			task.chanID, task.commitHeight,
		)
		if err != nil {
			err = fmt.Errorf("Unable to mark task chanid=%s "+
				"commit-height=%d ineligible: %v", task.chanID,
				task.commitHeight, err)
			log.Error(err)
			panic(err)
		}

		// If this task was rejected *and* the session had available
		// capacity, we discard anything held in the prevTask. Either it
		// was nil before, or is the task which was just rejected.
		c.prevTask = nil

	case ReserveExhausted:
		c.stats.sessionExhausted()

		log.Debugf("Session %s exhausted, backup chanid=%s "+
			"commit-height=%d queued for next session",
			c.sessionQueue.ID(), task.chanID, task.commitHeight)

		// Cache the task that we pulled off, so that we can process it
		// once a new session queue is available.
		c.sessionQueue = nil
		c.prevTask = task
	}
}

// dial connects the peer at addr using privKey as our secret key for the
// connection. The connection will use the configured Net's resolver to resolve
// the address for either Tor or clear net connections.
func (c *TowerClient) dial(privKey *btcec.PrivateKey,
	addr *lnwire.NetAddress) (wtserver.Peer, error) {

	return c.cfg.NetDial(privKey, addr, c.cfg.Net.Dial)
}

// readMessage receives and parses the next message from the given Peer. An
// error is returned if a message is not received before the server's read
// timeout, the read off the wire failed, or the message could not be
// deserialized.
func (c *TowerClient) readMessage(peer wtserver.Peer) (wtwire.Message, error) {
	// Set a read timeout to ensure we drop the connection if nothing is
	// received in a timely manner.
	err := peer.SetReadDeadline(time.Now().Add(c.cfg.ReadTimeout))
	if err != nil {
		err = fmt.Errorf("unable to set read deadline: %v", err)
		log.Errorf("Unable to read msg: %v", err)
		return nil, err
	}

	// Pull the next message off the wire,
	rawMsg, err := peer.ReadNextMessage()
	if err != nil {
		err = fmt.Errorf("unable to read message: %v", err)
		log.Errorf("Unable to read msg: %v", err)
		return nil, err
	}

	// Parse the received message according to the watchtower wire
	// specification.
	msgReader := bytes.NewReader(rawMsg)
	msg, err := wtwire.ReadMessage(msgReader, 0)
	if err != nil {
		err = fmt.Errorf("unable to parse message: %v", err)
		log.Errorf("Unable to read msg: %v", err)
		return nil, err
	}
	logMessage(peer, msg, true)

	return msg, nil
}

// sendMessage sends a watchtower wire message to the target peer.
func (c *TowerClient) sendMessage(peer wtserver.Peer, msg wtwire.Message) error {
	// Encode the next wire message into the buffer.
	// TODO(conner): use buffer pool
	var b bytes.Buffer
	_, err := wtwire.WriteMessage(&b, msg, 0)
	if err != nil {
		err = fmt.Errorf("Unable to encode msg: %v", err)
		log.Errorf("Unable to send msg: %v", err)
		return err
	}

	// Set the write deadline for the connection, ensuring we drop the
	// connection if nothing is sent in a timely manner.
	err = peer.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout))
	if err != nil {
		err = fmt.Errorf("unable to set write deadline: %v", err)
		log.Errorf("Unable to send msg: %v", err)
		return err
	}

	// Write out the full message to the remote peer.
	logMessage(peer, msg, false)
	_, err = peer.Write(b.Bytes())
	if err != nil {
		log.Errorf("Unable to send msg: %v", err)
	}
	return err
}

// logMessage writes information about a message received from a remote peer,
// using directional prepositions to signal whether the message was sent or
// received.
func logMessage(peer wtserver.Peer, msg wtwire.Message, read bool) {
	var action = "Received"
	var preposition = "from"
	if !read {
		action = "Sending"
		preposition = "to"
	}

	summary := wtwire.MessageSummary(msg)
	if len(summary) > 0 {
		summary = "(" + summary + ")"
	}

	log.Debugf("%s %s%v %s %x@%s", action, msg.MsgType(), summary,
		preposition, peer.RemotePub().SerializeCompressed(),
		peer.RemoteAddr())
}
