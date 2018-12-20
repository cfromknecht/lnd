// +build dev

package wtserver

import (
	"fmt"
	"net"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
)

type MockSigner struct {
	index uint32
	keys  map[keychain.KeyLocator]*btcec.PrivateKey
}

func NewMockSigner() *MockSigner {
	return &MockSigner{
		keys: make(map[keychain.KeyLocator]*btcec.PrivateKey),
	}
}

func (s *MockSigner) SignOutputRaw(tx *wire.MsgTx,
	signDesc *lnwallet.SignDescriptor) ([]byte, error) {

	witnessScript := signDesc.WitnessScript
	amt := signDesc.Output.Value

	privKey, ok := s.keys[signDesc.KeyDesc.KeyLocator]
	if !ok {
		panic("cannot sign w/ unknown key")
	}

	sig, err := txscript.RawTxInWitnessSignature(
		tx, signDesc.SigHashes, signDesc.InputIndex, amt,
		witnessScript, signDesc.HashType, privKey,
	)
	if err != nil {
		return nil, err
	}

	return sig[:len(sig)-1], nil
}

func (s *MockSigner) ComputeInputScript(tx *wire.MsgTx,
	signDesc *lnwallet.SignDescriptor) (*lnwallet.InputScript, error) {
	return nil, nil
}

func (s *MockSigner) AddPrivKey(privKey *btcec.PrivateKey) keychain.KeyLocator {
	keyLoc := keychain.KeyLocator{
		Index: s.index,
	}
	s.index++

	s.keys[keyLoc] = privKey

	return keyLoc
}

type MockPeer struct {
	remotePub  *btcec.PublicKey
	remoteAddr net.Addr

	IncomingMsgs chan []byte
	OutgoingMsgs chan []byte

	writeDeadline <-chan time.Time
	readDeadline  <-chan time.Time

	Quit chan struct{}
}

func NewMockPeer(pk *btcec.PublicKey, addr net.Addr, bufferSize int) *MockPeer {
	return &MockPeer{
		remotePub:    pk,
		remoteAddr:   addr,
		IncomingMsgs: make(chan []byte, bufferSize),
		OutgoingMsgs: make(chan []byte, bufferSize),
		Quit:         make(chan struct{}),
	}
}

func (p *MockPeer) Write(b []byte) (n int, err error) {
	select {
	case p.OutgoingMsgs <- b:
		return len(b), nil
	case <-p.writeDeadline:
		return 0, fmt.Errorf("write timeout expired")
	case <-p.Quit:
		return 0, fmt.Errorf("connection closed")
	}
}

func (p *MockPeer) Close() error {
	select {
	case <-p.Quit:
		return fmt.Errorf("connection already closed")
	default:
		close(p.Quit)
		return nil
	}
}

func (p *MockPeer) ReadNextMessage() ([]byte, error) {
	select {
	case b := <-p.IncomingMsgs:
		return b, nil
	case <-p.readDeadline:
		return nil, fmt.Errorf("read timeout expired")
	case <-p.Quit:
		return nil, fmt.Errorf("connection closed")
	}
}

func (p *MockPeer) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		p.writeDeadline = nil
		return nil
	}

	duration := time.Until(t)
	p.writeDeadline = time.After(duration)

	return nil
}

func (p *MockPeer) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		p.readDeadline = nil
		return nil
	}

	duration := time.Until(t)
	p.readDeadline = time.After(duration)

	return nil
}

func (p *MockPeer) RemotePub() *btcec.PublicKey {
	return p.remotePub
}

func (p *MockPeer) RemoteAddr() net.Addr {
	return p.remoteAddr
}
