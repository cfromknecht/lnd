package wtclient

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/lightningnetwork/lnd/watchtower/wtpolicy"
	"github.com/lightningnetwork/lnd/watchtower/wtserver"
	"github.com/lightningnetwork/lnd/watchtower/wtwire"
)

type SessionNegotiator interface {
	RequestSession()
	NewSessions() <-chan *wtdb.ClientSessionInfo
	Start() error
	Stop() error
}

type NegotiatorConfig struct {
	DB           DB
	Candidates   TowerCandidateIterator
	Policy       wtpolicy.Policy
	SweepFeeRate lnwallet.SatPerKWeight
	SendMessage  func(wtserver.Peer, wtwire.Message) error
	ReadMessage  func(wtserver.Peer) (wtwire.Message, error)
	Dial         func(*btcec.PrivateKey, *lnwire.NetAddress) (wtserver.Peer, error)
}

type sessionNegotiator struct {
	started uint32
	stopped uint32

	cfg *NegotiatorConfig

	dispatcher  chan struct{}
	newSessions chan *wtdb.ClientSessionInfo

	wg   sync.WaitGroup
	quit chan struct{}
}

func NewSessionNegotiator(cfg *NegotiatorConfig) *sessionNegotiator {
	return &sessionNegotiator{
		cfg:         cfg,
		dispatcher:  make(chan struct{}, 1),
		newSessions: make(chan *wtdb.ClientSessionInfo),
		quit:        make(chan struct{}),
	}
}

func (n *sessionNegotiator) NewSessions() <-chan *wtdb.ClientSessionInfo {
	return n.newSessions
}

func (n *sessionNegotiator) RequestSession() {
	select {
	case n.dispatcher <- struct{}{}:
	default:
	}
}

func (n *sessionNegotiator) Start() error {
	if !atomic.CompareAndSwapUint32(&n.started, 0, 1) {
		return nil
	}

	log.Debugf("Starting session negotiator")

	n.wg.Add(1)
	go n.negotiationDispatcher()

	return nil
}

func (n *sessionNegotiator) Stop() error {
	if !atomic.CompareAndSwapUint32(&n.stopped, 0, 1) {
		return nil
	}

	log.Debugf("Stopping session negotiator")

	close(n.quit)
	n.wg.Wait()

	return nil
}

func (n *sessionNegotiator) negotiationDispatcher() {
	defer n.wg.Done()

	successfulNegotiations := make(chan *wtdb.ClientSessionInfo)

	var isNegotiating bool
	for {
		select {
		case <-n.dispatcher:
			if isNegotiating {
				log.Debugf("Already negotiating session, ignoring")
				continue
			}
			isNegotiating = true

			// TODO(conner): consider reusing good towers

			log.Debugf("Dispatching session negotiation")

			n.wg.Add(1)
			go n.findTower(successfulNegotiations)

		case session := <-successfulNegotiations:
			select {
			case n.newSessions <- session:
			case <-n.quit:
				return
			}

			isNegotiating = false

		case <-n.quit:
			return
		}
	}
}

func (n *sessionNegotiator) findTower(
	successfulNegotiations chan *wtdb.ClientSessionInfo) {

	defer n.wg.Done()

	log.Debugf("Finding tower for session negotiation")
	n.cfg.Candidates.Reset()

	for {
		addr, err := n.cfg.Candidates.Next()
		if err != nil {
			// TODO(conner): queue after timeout
			fmt.Printf("unable to get new watchtower addr: %v\n",
				err)
			return
		}

		log.Debugf("Attempting session negotiation with tower=%x@%v",
			addr.IdentityKey.SerializeCompressed(),
			addr.Address.String())

		done := n.initSession(addr, successfulNegotiations)
		if done {
			log.Debugf("Request for session negotiation completed")
			return
		}
	}
}

func (n *sessionNegotiator) initSession(addr *lnwire.NetAddress,
	successfulNegotiations chan *wtdb.ClientSessionInfo) bool {

	tower, err := n.cfg.DB.CreateTower(addr)
	if err != nil {
		fmt.Printf("Unable to create new watchtower: %v\n", err)
		return false
	}

	// TODO(conner): create random pubkey
	sessionPrivKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		fmt.Printf("Unable to create session priv key: %v\n", err)
		return false
	}

	conn, err := n.cfg.Dial(sessionPrivKey, addr)
	if err != nil {
		fmt.Printf("Unable to connect to watchtower=%v: %v\n",
			addr, err)
		return false
	}

	localInit := wtwire.NewInitMessage(
		lnwire.NewRawFeatureVector(),
		lnwire.NewRawFeatureVector(wtwire.WtSessionsRequired),
	)

	// Send local Init message.
	log.Debugf("Sending Init message")
	err = n.cfg.SendMessage(conn, localInit)
	if err != nil {
		fmt.Printf("Unable to send init message to tower=%v: %v",
			addr, err)
		return false
	}

	log.Debugf("Init message sent")

	// Receive remote Init message.
	remoteMsg, err := n.cfg.ReadMessage(conn)
	if err != nil {
		fmt.Printf("Tower did not reply with Init message: %v", err)
		return false
	}
	remoteInit, ok := remoteMsg.(*wtwire.Init)
	if !ok {
		fmt.Printf("Expected Init from tower, received: %T", remoteMsg)
		return false
	}

	err = handleInit(localInit, remoteInit)
	if err != nil {
		fmt.Printf("Feature bit disagreement: %v", err)
		return false
	}

	// TODO(conner): validate required bits

	createSession := &wtwire.CreateSession{
		BlobType:     n.cfg.Policy.BlobType,
		MaxUpdates:   n.cfg.Policy.MaxUpdates,
		RewardRate:   n.cfg.Policy.RewardRate,
		SweepFeeRate: n.cfg.Policy.SweepFeeRate,
	}

	sessionID := wtdb.NewSessionIDFromPubKey(sessionPrivKey.PubKey())
	info := &wtdb.SessionInfo{
		ID:     sessionID,
		Policy: n.cfg.Policy,
	}

	// TODO(conner): write session info + privkey

	// Send SessionCreate message.
	err = n.cfg.SendMessage(conn, createSession)
	if err != nil {
		fmt.Printf("unable to send init message to watchtower=%v: %v\n",
			addr, err)
		return false
	}

	// Receive SessionCreateReply message.
	remoteMsg, err = n.cfg.ReadMessage(conn)
	if err != nil {
		fmt.Printf("Unable to read CreateSessionReply: %v\n", err)
		return false
	}

	createSessionReply, ok := remoteMsg.(*wtwire.CreateSessionReply)
	if !ok {
		fmt.Printf("Expected CreateSessionReply from tower, "+
			"received %T\n", remoteMsg)
		return false
	}

	switch createSessionReply.Code {
	case wtwire.CodeOK, wtwire.CreateSessionCodeAlreadyExists:
		// TODO(conner): validate reward address

		info.RewardAddress = createSessionReply.Data

		clientSession := &wtdb.ClientSessionInfo{
			Tower:          tower,
			SessionInfo:    *info,
			SessionPrivKey: sessionPrivKey,
		}

		// TODO(conner): save finalized client session

		err = n.cfg.DB.CreateClientSession(clientSession)
		if err != nil {
			fmt.Printf("Unable to save ClientSessionInfo: %v\n",
				err)
			return false
		}

		log.Debugf("New session negotiated!")
		select {
		case successfulNegotiations <- clientSession:
			return true
		case <-n.quit:
			return false
		}

	default:
		return false
	}
}

func handleInit(localInit, remoteInit *wtwire.Init) error {
	remoteLocalFeatures := lnwire.NewFeatureVector(
		remoteInit.LocalFeatures, wtwire.LocalFeatures,
	)
	remoteGlobalFeatures := lnwire.NewFeatureVector(
		remoteInit.GlobalFeatures, wtwire.GlobalFeatures,
	)

	unknownLocalFeatures := remoteLocalFeatures.UnknownRequiredFeatures()
	if len(unknownLocalFeatures) > 0 {
		err := fmt.Errorf("Peer set unknown local feature bits: %v",
			unknownLocalFeatures)
		return err
	}

	unknownGlobalFeatures := remoteGlobalFeatures.UnknownRequiredFeatures()
	if len(unknownGlobalFeatures) > 0 {
		err := fmt.Errorf("Peer set unknown global feature bits: %v",
			unknownGlobalFeatures)
		return err
	}

	return nil
}
