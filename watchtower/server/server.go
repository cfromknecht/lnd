package server

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/lightningnetwork/lnd/watchtower/wtwire"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/connmgr"
	"github.com/roasbeef/btcutil"
)

var (
	ErrPeerAlreadyConnected = errors.New("peer already connected")
)

type ConnFailure struct {
	ID   wtdb.SessionID
	Code uint16
}

func (f *ConnFailure) Error() string {
	return fmt.Sprintf("connection with session=%x failed with code=%v",
		f.ID, f.Code)
}

type Server struct {
	started  int32 // atomic
	shutdown int32 // atomic

	cfg *Config

	connMgr *connmgr.ConnManager

	peerMtx sync.RWMutex
	peers   map[wtdb.SessionID]*brontide.Conn

	wg   sync.WaitGroup
	quit chan struct{}
}

type Config struct {
	ListenAddrs []string
	DB          *wtdb.DB
	NodePrivKey *btcec.PrivateKey
	NewAddress  func() (btcutil.Address, error)
}

func New(cfg *Config) (*Server, error) {
	listeners := make([]net.Listener, len(cfg.ListenAddrs))
	for i, addr := range cfg.ListenAddrs {
		var err error
		listeners[i], err = brontide.NewListener(cfg.NodePrivKey, addr)
		if err != nil {
			return nil, err
		}
	}

	s := &Server{
		cfg:  cfg,
		quit: make(chan struct{}),
	}

	cmgr, err := connmgr.New(&connmgr.Config{
		Listeners: listeners,
		OnAccept:  s.InboundPeerConnected,
	})
	if err != nil {
		return nil, err
	}

	s.connMgr = cmgr

	return s, nil
}

func (s *Server) Start() error {
	// Already running?
	if !atomic.CompareAndSwapInt32(&s.started, 0, 1) {
		return nil
	}

	s.connMgr.Start()

	return nil
}

func (s *Server) Stop() error {
	// Bail if we're already shutting down.
	if !atomic.CompareAndSwapInt32(&s.shutdown, 0, 1) {
		return nil
	}

	s.connMgr.Stop()

	close(s.quit)
	s.wg.Wait()

	return nil
}

func (s *Server) InboundPeerConnected(c net.Conn) {
	conn, ok := c.(*brontide.Conn)
	if !ok {
		fmt.Println("incoming connection not brontide")
		c.Close()
		return
	}

	s.wg.Add(1)
	go s.handleIncomingConnection(conn)
}

func (s *Server) addPeer(id *wtdb.SessionID, conn *brontide.Conn) error {
	s.peerMtx.Lock()
	conn, ok := s.peers[*id]
	if ok {
		s.peerMtx.Unlock()
		return ErrPeerAlreadyConnected
	}
	s.peers[*id] = conn
	s.peerMtx.Unlock()

	return nil
}

func (s *Server) removePeer(id *wtdb.SessionID) {
	s.peerMtx.Lock()
	conn, ok := s.peers[*id]
	delete(s.peers, *id)
	s.peerMtx.Unlock()

	if ok {
		conn.Close()
	}
}

func (s *Server) handleIncomingConnection(conn *brontide.Conn) {
	defer s.wg.Done()

	id := wtdb.NewSessionIDFromPubKey(conn.RemotePub())

	err := s.addPeer(&id, conn)
	if err != nil {
		failConn(conn, &id, 0)
		return
	}
	defer s.removePeer(&id)

	var isFirstMessage = true
	for {
		select {
		case <-s.quit:
			failConn(conn, &id, 0)
			return
		default:
		}

		err = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		if err != nil {
			fmt.Printf("unable to set read deadline: %v\n", err)
			return
		}

		rawMsg, err := conn.ReadNextMessage()
		if err != nil {
			fmt.Printf("unable to read message: %v\n", err)
			return
		}

		select {
		case <-s.quit:
			failConn(conn, &id, 0)
			return
		default:
		}

		msgReader := bytes.NewReader(rawMsg)
		nextMsg, err := wtwire.ReadMessage(msgReader, 0)
		if err != nil {
			fmt.Printf("unable to parse message: %v\n", err)
			return
		}

		switch msg := nextMsg.(type) {
		case *wtwire.SessionInit:
			if !isFirstMessage {
				failConn(conn, &id, 0)
				return
			}

			fmt.Println("got info:", msg)
			if err := s.handleSessionInit(conn, &id, msg); err != nil {
				fmt.Printf("unable to handle session init: %v\n", err)
				return
			}

			// TODO(conner): wait for payment

		case *wtwire.StateUpdate:
			fmt.Println("got txid:", hex.EncodeToString(msg.Hint[:]))
			fmt.Println("got blob:", hex.EncodeToString(msg.EncryptedBlob[:]))
			fmt.Println(string(rawMsg))
			if err := s.handleStateUpdate(conn, &id, msg); err != nil {
				fmt.Printf("unable to handle state update: %v\n", err)
				return
			}

		default:
			fmt.Println("unknown message")
			return
		}

		isFirstMessage = false
	}
}

func (s *Server) handleSessionInit(conn *brontide.Conn,
	id *wtdb.SessionID, init *wtwire.SessionInit) error {

	// TODO(conner): validate init against policy

	_, err := s.cfg.DB.GetSessionInfo(id)
	switch {
	case err == nil:
		return failConn(conn, id, 0)
	case err != wtdb.ErrSessionNotFound:
		return failConn(conn, id, 0)
	}

	rewardAddress, err := s.cfg.NewAddress()
	if err != nil {
		return failConn(conn, id, 0)
	}

	info := wtdb.SessionInfo{
		ID:            *id,
		Version:       init.Version,
		MaxUpdates:    init.MaxUpdates,
		RewardRate:    init.RewardRate,
		SweepFeeRate:  init.SweepFeeRate,
		RewardAddress: []byte(rewardAddress.EncodeAddress()),
	}

	err = s.cfg.DB.InsertSessionInfo(&info)
	if err != nil {
		return failConn(conn, id, 0)
	}

	accept := &wtwire.SessionAccept{}

	return sendMessage(conn, accept)
}

func (s *Server) handleStateUpdate(conn *brontide.Conn,
	id *wtdb.SessionID, update *wtwire.StateUpdate) error {

	sessionUpdate := wtdb.SessionStateUpdate{
		ID:            *id,
		Hint:          update.Hint,
		SeqNum:        update.SeqNum,
		LastApplied:   update.LastApplied,
		EncryptedBlob: update.EncryptedBlob,
	}

	err := s.cfg.DB.InsertStateUpdate(&sessionUpdate)
	if err != nil {
		return failConn(conn, id, 0)
	}

	return ackMessage(conn, update.SeqNum)
}

func sendMessage(conn *brontide.Conn, msg wtwire.Message) error {
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

func ackMessage(conn *brontide.Conn, seqNum uint16) error {
	ack := &wtwire.Ack{
		LastApplied: seqNum,
	}

	return sendMessage(conn, ack)
}

func failConn(conn *brontide.Conn, id *wtdb.SessionID, code uint16) error {
	fail := &wtwire.Fail{
		Code: code,
	}

	err := sendMessage(conn, fail)
	if err != nil {
		log.Printf("unable to send fail msg: %v\n", fail)
	} else {
		log.Printf("sent fail msg: %v\n", fail)
	}

	return &ConnFailure{
		ID:   *id,
		Code: code,
	}
}
