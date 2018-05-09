package server

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lightninglabs/sauron/config"
	"github.com/lightninglabs/sauron/transactiondb"
	"github.com/lightninglabs/sauron/wtwire"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/connmgr"
	"github.com/roasbeef/btcutil"
)

type Server struct {
	started  int32 // atomic
	shutdown int32 // atomic

	identityPriv  *btcec.PrivateKey
	connMgr       *connmgr.ConnManager
	rewardAddress btcutil.Address

	db *transactiondb.DB

	wg sync.WaitGroup
}

func New(listenAddrs []string, privKey *btcec.PrivateKey,
	db *transactiondb.DB, address btcutil.Address) (*Server, error) {

	var err error
	listeners := make([]net.Listener, len(listenAddrs))
	for i, addr := range listenAddrs {
		listeners[i], err = brontide.NewListener(privKey, addr)
		if err != nil {
			return nil, err
		}
	}
	s := &Server{
		identityPriv:  privKey,
		rewardAddress: address,
		db:            db,
	}
	cmgr, err := connmgr.New(&connmgr.Config{
		Listeners:      listeners,
		OnAccept:       s.InboundPeerConnected,
		RetryDuration:  time.Second * 5,
		TargetOutbound: 100,
		GetNewAddress:  nil,
		Dial:           config.NoiseDial(s.identityPriv),
		OnConnection:   s.OutboundPeerConnected,
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

	s.wg.Add(1)
	go s.connMgr.Start()
	return nil
}

func (s *Server) Stop() error {
	// Bail if we're already shutting down.
	if !atomic.CompareAndSwapInt32(&s.shutdown, 0, 1) {
		return nil
	}

	s.connMgr.Stop()
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

func (s *Server) handleIncomingConnection(conn *brontide.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	if err := s.handshake(conn); err != nil {
		fmt.Println("handhsake failed", err)
		return
	}

	for {
		rawMsg, err := conn.ReadNextMessage()
		if err != nil {
			fmt.Println(err)
			return
		}
		msgReader := bytes.NewReader(rawMsg)
		nextMsg, err := wtwire.ReadMessage(msgReader, 0)
		if err != nil {
			fmt.Println(err)
			continue
		}

		switch msg := nextMsg.(type) {
		case *wtwire.SessionInfo:
			fmt.Println("got info:", msg)
			if err := s.handleSessionInfo(msg); err != nil {
				fmt.Println(err)
				continue
			}
			if err := ackMessage(conn); err != nil {
				fmt.Println(err)
				// TODO:handle
				continue
			}
		case *wtwire.StateUpdate:

			fmt.Println("got txid:", hex.EncodeToString(msg.TxIDPrefix[:]))
			fmt.Println("got blob:", hex.EncodeToString(msg.EncryptedBlob[:]))
			fmt.Println(string(rawMsg))
			if err := s.handleStateUpdate(msg); err != nil {
				fmt.Println(err)
				// TODO: handle
				continue
			}
			if err := ackMessage(conn); err != nil {
				fmt.Println(err)
				// TODO:handle
				continue
			}
		default:
			fmt.Println("unknown message")
		}
	}
}

func (s *Server) handshake(conn *brontide.Conn) error {
	rawMsg, err := conn.ReadNextMessage()
	if err != nil {
		return err
	}

	msgReader := bytes.NewReader(rawMsg)
	msg, err := wtwire.ReadMessage(msgReader, 0)
	if err != nil {
		return err
	}

	req, ok := msg.(*wtwire.WatchRequest)
	if !ok {
		return fmt.Errorf("received malformed watch request")
	}

	script := s.rewardAddress.ScriptAddress()
	if len(script) != 20 {
		return fmt.Errorf("output address lenght unknown")
	}

	var outputScript [20]byte
	copy(outputScript[:], script)
	resp := &wtwire.WatchResponse{
		SessionID:    req.SessionID,
		Accept:       1,
		OutputScript: outputScript,
	}

	if err := sendMessage(resp, conn); err != nil {
		return err
	}

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

func ackMessage(conn *brontide.Conn) error {
	ack := &wtwire.Ack{}
	return sendMessage(ack, conn)
}

func (s *Server) clientHandler(conn *brontide.Conn) {
	defer s.wg.Done()
}

func (s *Server) handleSessionInfo(info *wtwire.SessionInfo) error {
	return s.db.InsertSessionInfo(info)
}

func (s *Server) handleStateUpdate(blob *wtwire.StateUpdate) error {
	return s.db.InsertTransaction(blob)
}

func (s *Server) OutboundPeerConnected(connReq *connmgr.ConnReq, conn net.Conn) {
	fmt.Println("got outbound requesjt")
}
