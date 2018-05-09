package client

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lightninglabs/sauron/config"
	"github.com/lightninglabs/sauron/justicekit"
	"github.com/lightninglabs/sauron/wtwire"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil/txsort"
)

const (
	defaultTowerRewardPerThousand = 100
	defaultNumWatchers            = 5
	ackTimeoutMs                  = 5000
)

var (
	defaultServerAddress = &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: config.DefaultServerPort,
	}
	defaultTowers = []*lnwire.NetAddress{
		{
			IdentityKey: config.ServerPrivKey.PubKey(),
			Address:     defaultServerAddress,
		},
	}
)

// RevokedCommitment constains the information needed by the client for every
// channel state update, to be able to determine what to send to the watcher.
type RevokedCommitment struct {
	ShortChanID   uint64
	LocalBalance  lnwire.MilliSatoshi
	RemoteBalance lnwire.MilliSatoshi
	Height        uint64
	Revocation    [32]byte
}

// towerConfig contains the necessary information about a watchtower
// needed to establish a connection to it.
type towerConfig struct {
	addr *lnwire.NetAddress
}

// chanInfo contains the permanent parameters of a channel, necessary
// to be able to construct commitment and penalty transactions on each
// state update.
type chanInfo struct {
	// btcutil.Amount instead?
	feeRate      uint64
	outputScript []byte

	localChanCfg        *channeldb.ChannelConfig
	remoteChanCfg       *channeldb.ChannelConfig
	fundingTxIn         *wire.TxIn
	stateHintObfuscator [lnwallet.StateHintSize]byte
}

// watchSession is a struct holding all necessary info needed for one
// watch session. A watch session is defined as one client<->server
// relationship where the server (watchtower) is watching one channel.
type watchSession struct {
	// shortChanID is the actual shortChanID of the channel
	// of this watch session.
	shortChanID uint64

	// sessionID is the temporary channel ID used uniquely
	// for this watch session. We use such an ID for the
	// watchtower not to be able to determine which channel
	// it is actually watching.
	sessionID uint64

	tower *towerConfig
	info  *chanInfo

	towerOutputScript []byte
	towerReward       uint64

	// queue holds the incoming state updates for this channel.
	qMtx  sync.Mutex
	queue []*RevokedCommitment

	signalPending chan struct{}
}

// Client is a module that takes care of finding and communicating with
// watchtowers. For each channel state update given to the Client, it
// wil distribute this state to a set of watchers, that will be able
// to punish the channel counterparty if he breaches any of these states.
type Client struct {
	started  int32 // atomic
	shutdown int32 // atomic

	signer lnwallet.Signer

	// identityPriv is used for the brontide connection to the
	// watchtowers.
	identityPriv *btcec.PrivateKey

	// <shortChanID>:[]session
	actSesMtx      sync.RWMutex
	activeSessions map[uint64][]*watchSession

	wg   sync.WaitGroup
	quit chan struct{}
}

// New returns a new Client.
func New(privKey *btcec.PrivateKey, signer lnwallet.Signer) (*Client, error) {
	c := &Client{
		identityPriv:   privKey,
		signer:         signer,
		activeSessions: make(map[uint64][]*watchSession),
		quit:           make(chan struct{}),
	}
	return c, nil
}

// Start starts the Client and its send loop, making it ready to
// receive channels to distribute to watchtowers.
func (c *Client) Start() error {
	// Already running?
	if !atomic.CompareAndSwapInt32(&c.started, 0, 1) {
		return nil
	}

	return nil
}

// Stop stops this Client.
func (c *Client) Stop() error {
	// Bail if we're already shutting down.
	if !atomic.CompareAndSwapInt32(&c.shutdown, 0, 1) {
		return nil
	}

	close(c.quit)
	c.wg.Wait()

	return nil
}

// WatchChannel attempts to find watchtowers willing to start
// watching the given channel. New state for this channel will
// be sent to the found towers. Note that the provided parameters
// will apply to the remote node's commitment transaction, making
// the to_local output be the delayed output paying the remote node.
func (c *Client) WatchChannel(shortChanID uint64, fundingTxIn *wire.TxIn,
	localChanCfg, remoteChanCfg *channeldb.ChannelConfig,
	feeRate uint64, outputScript []byte) error {

	c.actSesMtx.RLock()
	if _, ok := c.activeSessions[shortChanID]; ok {
		c.actSesMtx.RUnlock()
		return fmt.Errorf("already watching channel")
	}
	c.actSesMtx.RUnlock()

	channelInfo := &chanInfo{
		feeRate:       feeRate,
		outputScript:  outputScript,
		localChanCfg:  localChanCfg,
		remoteChanCfg: remoteChanCfg,
		fundingTxIn:   fundingTxIn,
	}

	sessions, err := c.newWatchSessions(shortChanID, channelInfo)
	if err != nil {
		return err
	}

	c.actSesMtx.Lock()
	c.activeSessions[shortChanID] = sessions
	c.actSesMtx.Unlock()

	// Launch a goroutine responisble for handling each sesison.
	for _, s := range sessions {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()

			// We start and run a watch session. If this
			// fails at some point, we must restart it,
			// to make sure we have enough towers watching
			// the channel.
			for {
				if err := c.runWatchSession(s); err != nil {
					fmt.Println(err)

					// If we failed, and we are not quitting,
					// start a new run.
					select {
					case <-c.quit:
						return
					default:
					}
				}
			}
		}()
	}
	return nil
}

// QueueNewState will add a new channel state to the pipeline of states
// that will be signed and distributed to the watchtowers watching
// this channel.
func (c *Client) QueueNewState(state *RevokedCommitment) error {

	// Add this update to the queues of all the watch session for this
	// channel.
	c.actSesMtx.RLock()
	for _, s := range c.activeSessions[state.ShortChanID] {
		s.qMtx.Lock()
		s.queue = append(s.queue, state)
		s.qMtx.Unlock()
		s.signalPending <- struct{}{}
	}
	c.actSesMtx.RUnlock()

	return nil
}

func (c *Client) runWatchSession(s *watchSession) error {
	// We cannot continue before we have found a tower willing to watch the
	// channel.
FindTower:
	for s.tower == nil {

		twrs, err := c.fetchTowers(1)
		if err != nil {
			return err
		}

		// Check if we found a tower not already watching this channel.
		for _, twr := range twrs {
			id := string(twr.addr.IdentityKey.SerializeCompressed())
			alreadyWatching := false

			c.actSesMtx.RLock()
			for _, a := range c.activeSessions[s.shortChanID] {
				if a.tower != nil &&
					id == string(a.tower.addr.IdentityKey.SerializeCompressed()) {
					alreadyWatching = true
				}
			}
			c.actSesMtx.RUnlock()
			if !alreadyWatching {
				// We found a new tower not already
				// watching this channel.
				s.tower = twr
				break FindTower
			}
		}

		select {
		// TODO: Longer/exp backoff?
		case <-time.After(5 * time.Second):
			// Retry
		case <-c.quit:
			return nil

		}
	}

	// Now that we have a tower to watch this channel, we will connect to
	// it, send a watch request, and wait for a watch response.
	conn, err := c.connect(s.tower)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := c.handshake(conn, s); err != nil {
		return err
	}

	// Send the initial channel information to the tower.
	sessionInfo := &wtwire.SessionInfo{
		SessionID:             s.sessionID,
		RevocationBasePoint:   s.info.remoteChanCfg.RevocationBasePoint,
		LocalDelayedBasePoint: s.info.remoteChanCfg.DelayBasePoint,
		CsvDelay:              s.info.remoteChanCfg.CsvDelay,
		OutputScript:          s.info.outputScript,
		TowerOutputScript:     s.towerOutputScript,
		OutputReward:          s.towerReward,
		FeeRate:               s.info.feeRate,
	}

	if err := c.sendAndAwaitAck(sessionInfo, conn); err != nil {
		return err
	}

	// Session with the watchtower is now ready, we start handling incoming
	// updates to our queue of revoked commitments.
	for {
		select {
		case <-s.signalPending:
			for len(s.queue) > 0 {
				s.qMtx.Lock()
				rev := s.queue[0]
				s.queue[0] = nil
				s.queue = s.queue[1:]
				s.qMtx.Unlock()

				err := c.sendStateUpdate(s, rev, conn)
				if err != nil {
					return err
				}
			}

		case <-c.quit:
			return nil
		}
	}

	return nil
}

func (c *Client) connect(tower *towerConfig) (*brontide.Conn, error) {

	// TODO: use new public key for each connection.

	// Must establish connection before we can continue.
	conn, err := brontide.Dial(c.identityPriv, tower.addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (c *Client) handshake(conn *brontide.Conn, s *watchSession) error {
	// Send a watch request for this channel.
	req := &wtwire.WatchRequest{
		SessionID:    s.sessionID,
		OutputReward: s.towerReward,
	}

	if err := sendMessage(req, conn); err != nil {
		return err
	}

	// Wait for response.
	rawMsg, err := conn.ReadNextMessage()
	if err != nil {
		return err

	}

	msgReader := bytes.NewReader(rawMsg)
	msg, err := wtwire.ReadMessage(msgReader, 0)
	if err != nil {
		return err
	}

	resp, ok := msg.(*wtwire.WatchResponse)
	if !ok {
		return fmt.Errorf("received malformed watch response")
	}

	if resp.Accept != 1 {
		return fmt.Errorf("tower did not accept watch request")
	}

	// Remember script tower wants to get paid to.
	s.towerOutputScript = resp.OutputScript[:]

	return nil
}

func sendMessage(msg wtwire.Message, conn *brontide.Conn) error {
	var b bytes.Buffer
	_, err := wtwire.WriteMessage(&b, msg, 0)
	if err != nil {
		return err
	}
	_, err = conn.Write(b.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) sendAndAwaitAck(msg wtwire.Message, conn *brontide.Conn) error {
	if err := sendMessage(msg, conn); err != nil {
		return err
	}

	// Await ack, fail if takes too long.
	errChan := make(chan error)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		// TODO: how to kill a blocking call here?
		rawMsg, err := conn.ReadNextMessage()
		if err != nil {
			errChan <- err
		}

		msgReader := bytes.NewReader(rawMsg)
		msg, err := wtwire.ReadMessage(msgReader, 0)
		if err != nil {
			errChan <- err
		}

		_, ok := msg.(*wtwire.Ack)
		if !ok {
			errChan <- fmt.Errorf("received malformed ack")
		}
		close(errChan)

	}()
	select {
	case err := <-errChan:
		return err
	case <-time.After(ackTimeoutMs * time.Millisecond):
		return fmt.Errorf("timeout waiting for ACK")
	}
}

func (c *Client) sendStateUpdate(s *watchSession, rev *RevokedCommitment,
	conn *brontide.Conn) error {

	sign, txid, err := c.signState(s, rev)
	if err != nil {
		return err
	}

	sweep := &justicekit.SweepDetails{
		Revocation: rev.Revocation,
		SweepSig:   sign,
	}

	enc, err := justicekit.EncryptSweepDetails(sweep, txid)
	if err != nil {
		return err
	}

	// TODO: define this constant somewhere when finalized.
	var blob [112]byte
	if len(enc) != 112 {
		return fmt.Errorf("enc not 112")
	}
	copy(blob[:], enc)

	var txPrefix [16]byte
	copy(txPrefix[:], txid[:16])
	upd := &wtwire.StateUpdate{
		SessionID:     s.sessionID,
		TxIDPrefix:    txPrefix,
		EncryptedBlob: blob,
	}

	if err := c.sendAndAwaitAck(upd, conn); err != nil {
		return err
	}
	return nil
}

func assembleCommitment(s *watchSession, rev *RevokedCommitment) (*wire.MsgTx, error) {

	_, commitmentPoint := btcec.PrivKeyFromBytes(btcec.S256(),
		rev.Revocation[:])

	// With the commitment point generated, we can now generate the four
	// keys we'll need to reconstruct the commitment state,
	keyRing := lnwallet.DeriveCommitmentKeys(commitmentPoint, false,
		s.info.localChanCfg, s.info.remoteChanCfg)

	ourBalance := rev.LocalBalance
	theirBalance := rev.RemoteBalance

	delay := uint32(s.info.remoteChanCfg.CsvDelay)
	delayBalance := theirBalance.ToSatoshis()
	p2wkhBalance := ourBalance.ToSatoshis()

	// Generate a new commitment transaction with all the latest
	// unsettled/un-timed out HTLCs.
	commitTx, err := lnwallet.CreateCommitTx(s.info.fundingTxIn, keyRing,
		delay, delayBalance, p2wkhBalance, s.info.remoteChanCfg.DustLimit)
	if err != nil {
		return nil, err
	}

	// Set the state hint of the commitment transaction to facilitate
	// quickly recovering the necessary penalty state in the case of an
	// uncooperative broadcast.
	err = lnwallet.SetStateNumHint(commitTx, rev.Height,
		s.info.stateHintObfuscator)
	if err != nil {
		return nil, err
	}

	// Sort the transactions according to the agreed upon canonical
	// ordering. This lets us skip sending the entire transaction over,
	// instead we'll just send signatures.
	txsort.InPlaceSort(commitTx)

	return commitTx, nil
}

func (c *Client) signState(s *watchSession, rev *RevokedCommitment) (*btcec.Signature, *chainhash.Hash, error) {

	commitmentSecret, _ := btcec.PrivKeyFromBytes(btcec.S256(),
		rev.Revocation[:])

	// Generate a new commitment transaction with all the latest
	// unsettled/un-timed out HTLCs.
	commitTx, err := assembleCommitment(s, rev)
	if err != nil {
		return nil, nil, err
	}

	commitHash := commitTx.TxHash()

	penaltyTx, remotePkScript, err := justicekit.AssemblePenaltyTx(
		commitTx, s.info.localChanCfg.RevocationBasePoint,
		s.info.remoteChanCfg.DelayBasePoint,
		s.info.remoteChanCfg.CsvDelay, s.info.feeRate, s.towerReward,
		s.info.outputScript, s.towerOutputScript, rev.Revocation)
	if err != nil {
		return nil, nil, err
	}

	remoteWitnessHash, err := lnwallet.WitnessScriptHash(remotePkScript)
	if err != nil {
		return nil, nil, err
	}

	// Conditionally instantiate a sign descriptor for each of the
	// commitment outputs. If either is considered dust using the remote
	// party's dust limit, the respective sign descriptor will be nil.
	var remoteSignDesc *lnwallet.SignDescriptor

	// Compute the local and remote balances in satoshis.
	remoteAmt := rev.RemoteBalance.ToSatoshis()

	// Similarly, if the remote balance exceeds the remote party's dust
	// limit, assemble the remote sign descriptor.
	if remoteAmt >= s.info.remoteChanCfg.DustLimit {
		remoteSignDesc = &lnwallet.SignDescriptor{
			// TODO: ensure this is the correct key.
			PubKey:        s.info.localChanCfg.RevocationBasePoint,
			DoubleTweak:   commitmentSecret,
			WitnessScript: remotePkScript,
			Output: &wire.TxOut{
				PkScript: remoteWitnessHash,
				Value:    int64(remoteAmt),
			},
			// Let watchtower add inputs to bump the fee if neccessary.
			HashType: txscript.SigHashSingle, // | txscript.SigHashAnyOneCanPay,
		}
	}

	hashCache := txscript.NewTxSigHashes(penaltyTx)
	remoteSignDesc.SigHashes = hashCache
	witness, err := lnwallet.CommitSpendRevoke(c.signer, remoteSignDesc,
		penaltyTx)
	if err != nil {
		return nil, nil, err
	}
	penaltyTx.TxIn[0].Witness = witness

	fmt.Println("will check sig for ", penaltyTx.TxHash())
	fmt.Println("prev tx has hash", commitTx.TxHash())

	// Prove that the transaction has been validly signed by executing the
	// script pair.
	flags := txscript.StandardVerifyFlags
	vm, err := txscript.NewEngine(
		remoteWitnessHash, penaltyTx, 0, flags,
		nil, nil, int64(remoteAmt))
	if err != nil {
		return nil, nil, err
	}
	if err := vm.Execute(); err != nil {
		return nil, nil, err
	}
	fmt.Println("Transaction successfully signed")
	sign, err := btcec.ParseSignature(witness[0], btcec.S256())
	if err != nil {
		return nil, nil, err
	}

	return sign, &commitHash, nil
}

func (c *Client) newWatchSessions(shortChanID uint64, info *chanInfo) ([]*watchSession, error) {

	// Try to find towers ready to watch this channel.
	numTowers := defaultNumWatchers
	twrs, err := c.fetchTowers(numTowers)
	if err != nil {
		return nil, err
	}

	sessions := make([]*watchSession, numTowers)
	for i := range sessions {
		// TODO: use random/blinded sessionID.
		sessionID := shortChanID

		// Now assign one tower to each channel. If not enough
		// towers were found, the watch session won't have any
		// assigned tower, and must find one at a later point.
		var twr *towerConfig
		if i < len(twrs) {
			twr = twrs[i]
		}
		sessions[i] = &watchSession{
			shortChanID:   shortChanID,
			sessionID:     sessionID,
			tower:         twr,
			towerReward:   defaultTowerRewardPerThousand,
			info:          info,
			signalPending: make(chan struct{}, 1),
		}
	}
	return sessions, nil
}

// fetchTowers will gather a list of (random?) active towers.
func (c *Client) fetchTowers(num int) ([]*towerConfig, error) {
	var twrs []*towerConfig

	// TODO: random dns?
	for _, addr := range defaultTowers {
		twr := &towerConfig{
			addr: addr,
		}
		twrs = append(twrs, twr)
	}

	if len(twrs) < num {
		num = len(twrs)
	}

	return twrs[:num], nil
}
