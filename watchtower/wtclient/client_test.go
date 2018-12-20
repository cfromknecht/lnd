// +build dev

package wtclient_test

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/watchtower/wtclient"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/lightningnetwork/lnd/watchtower/wtpolicy"
	"github.com/lightningnetwork/lnd/watchtower/wtserver"
)

const csvDelay uint32 = 144

var (
	revPrivBytes = []byte{
		0x8f, 0x4b, 0x51, 0x83, 0xa9, 0x34, 0xbd, 0x5f,
		0x74, 0x6c, 0x9d, 0x5c, 0xae, 0x88, 0x2d, 0x31,
		0x06, 0x90, 0xdd, 0x8c, 0x9b, 0x31, 0xbc, 0xd1,
		0x78, 0x91, 0x88, 0x2a, 0xf9, 0x74, 0xa0, 0xef,
	}

	toLocalPrivBytes = []byte{
		0xde, 0x17, 0xc1, 0x2f, 0xdc, 0x1b, 0xc0, 0xc6,
		0x59, 0x5d, 0xf9, 0xc1, 0x3e, 0x89, 0xbc, 0x6f,
		0x01, 0x85, 0x45, 0x76, 0x26, 0xce, 0x9c, 0x55,
		0x3b, 0xc9, 0xec, 0x3d, 0xd8, 0x8b, 0xac, 0xa8,
	}

	toRemotePrivBytes = []byte{
		0x28, 0x59, 0x6f, 0x36, 0xb8, 0x9f, 0x19, 0x5d,
		0xcb, 0x07, 0x48, 0x8a, 0xe5, 0x89, 0x71, 0x74,
		0x70, 0x4c, 0xff, 0x1e, 0x9c, 0x00, 0x93, 0xbe,
		0xe2, 0x2e, 0x68, 0x08, 0x4c, 0xb4, 0x0f, 0x4f,
	}

	// addr is the server's reward address given to watchtower clients.
	addr, _ = btcutil.DecodeAddress(
		"mrX9vMRYLfVy1BnZbc5gZjuyaqH3ZW2ZHz", &chaincfg.TestNet3Params,
	)

	addrScript, _ = txscript.PayToAddrScript(addr)
)

// randPrivKey generates a new secp keypair, and returns the public key.
func randPrivKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()

	sk, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatalf("unable to generate pubkey: %v", err)
	}

	return sk
}

type mockNet struct {
	connCallback func(wtserver.Peer)
}

func newMockNet(cb func(wtserver.Peer)) *mockNet {
	return &mockNet{
		connCallback: cb,
	}
}

func (m *mockNet) Dial(network string, address string) (net.Conn, error) {
	return nil, nil
}

func (m *mockNet) LookupHost(host string) ([]string, error) {
	panic("not implemented")
}

func (m *mockNet) LookupSRV(service string, proto string, name string) (string, []*net.SRV, error) {
	panic("not implemented")
}

func (m *mockNet) ResolveTCPAddr(network string, address string) (*net.TCPAddr, error) {
	panic("not implemented")
}

func (m *mockNet) AuthDial(localPriv *btcec.PrivateKey, netAddr *lnwire.NetAddress,
	dialer func(string, string) (net.Conn, error)) (wtserver.Peer, error) {

	localPk := localPriv.PubKey()
	localAddr := &net.TCPAddr{
		IP:   net.IP{0x32, 0x31, 0x30, 0x29},
		Port: 36723,
	}

	localPeer, remotePeer := wtserver.NewMockConn(
		localPk, netAddr.IdentityKey, localAddr, netAddr.Address, 0,
	)

	m.connCallback(remotePeer)

	return localPeer, nil
}

func TestWatchtowerClient(t *testing.T) {
	const (
		localAmount  = btcutil.Amount(100000)
		remoteAmount = btcutil.Amount(200000)
		totalAmount  = localAmount + remoteAmount
	)

	// Parse the key pairs for all keys used in the test.
	revSK, revPK := btcec.PrivKeyFromBytes(
		btcec.S256(), revPrivBytes,
	)
	_, toLocalPK := btcec.PrivKeyFromBytes(
		btcec.S256(), toLocalPrivBytes,
	)
	toRemoteSK, toRemotePK := btcec.PrivKeyFromBytes(
		btcec.S256(), toRemotePrivBytes,
	)

	signer := wtserver.NewMockSigner()
	var (
		revKeyLoc      = signer.AddPrivKey(revSK)
		toRemoteKeyLoc = signer.AddPrivKey(toRemoteSK)
	)

	// Construct the to-local witness script.
	toLocalScript, err := lnwallet.CommitScriptToSelf(
		csvDelay, toLocalPK, revPK,
	)
	if err != nil {
		t.Fatalf("unable to create to-local script: %v", err)
	}

	// Compute the to-local witness script hash.
	toLocalScriptHash, err := lnwallet.WitnessScriptHash(toLocalScript)
	if err != nil {
		t.Fatalf("unable to create to-local witness script hash: %v", err)
	}

	// Compute the to-remote witness script hash.
	toRemoteScriptHash, err := lnwallet.CommitScriptUnencumbered(toRemotePK)
	if err != nil {
		t.Fatalf("unable to create to-remote script: %v", err)
	}

	// Construct the breaching commitment txn, containing the to-local and
	// to-remote outputs. We don't need any inputs for this test.
	breachTxn := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{},
		TxOut: []*wire.TxOut{
			{
				Value:    int64(localAmount),
				PkScript: toLocalScriptHash,
			},
			{
				Value:    int64(remoteAmount),
				PkScript: toRemoteScriptHash,
			},
		},
	}

	towerAddrStr := "18.28.243.2:9911"
	towerTCPAddr, err := net.ResolveTCPAddr("tcp", towerAddrStr)
	if err != nil {
		t.Fatalf("Unable to resolve tower TCP addr: %v", err)
	}

	privKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatalf("Unable to generate tower private key: %v", err)
	}

	towerPubKey := privKey.PubKey()

	towerAddr := &lnwire.NetAddress{
		IdentityKey: towerPubKey,
		Address:     towerTCPAddr,
	}

	const timeout = 5 * time.Second
	serverDB := wtdb.NewMockDB()
	server, err := wtserver.New(&wtserver.Config{
		DB:           serverDB,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		NewAddress: func() (btcutil.Address, error) {
			return addr, nil
		},
	})
	if err != nil {
		t.Fatalf("Unable to create wtserver: %v", err)
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Unable to start wtserver: %v", err)
	}
	defer server.Stop()

	mockNet := newMockNet(server.InboundPeerConnected)

	policy := wtpolicy.DefaultPolicy()
	policy.MaxUpdates = 5

	cfg := &wtclient.Config{
		Signer:       signer,
		Net:          mockNet,
		DB:           wtclient.NewMockDB(),
		NetDial:      mockNet.AuthDial,
		PrivateTower: towerAddr,
		Policy:       policy,
		NewAddress: func() ([]byte, error) {
			return addrScript, nil
		},
	}
	client, err := wtclient.New(cfg)
	if err != nil {
		t.Fatalf("Unable to create wtclient: %v", err)
	}

	if err = client.Start(); err != nil {
		t.Fatalf("Unable to start wtclient: %v", err)
	}
	defer client.Stop()

	commitKeyRing := &lnwallet.CommitmentKeyRing{
		RevocationKey: revPK,
		NoDelayKey:    toLocalPK,
		DelayKey:      toRemotePK,
	}

	// Create the sign descriptor used to sign for the to-local input.
	toLocalSignDesc := &lnwallet.SignDescriptor{
		KeyDesc: keychain.KeyDescriptor{
			KeyLocator: revKeyLoc,
			PubKey:     revPK,
		},
		WitnessScript: toLocalScript,
		Output:        breachTxn.TxOut[0],
		HashType:      txscript.SigHashAll,
	}

	// Create the sign descriptor used to sign for the to-remote input.
	toRemoteSignDesc := &lnwallet.SignDescriptor{
		KeyDesc: keychain.KeyDescriptor{
			KeyLocator: toRemoteKeyLoc,
			PubKey:     toRemotePK,
		},
		WitnessScript: toRemoteScriptHash,
		Output:        breachTxn.TxOut[1],
		HashType:      txscript.SigHashAll,
	}

	newBreach := func(i int32) *lnwallet.BreachRetribution {
		// Copy the breach transaction and change the transaction
		// version. This allows us to change the txid (and therefore,
		// breach hint) without needing to change the signing keys.
		btx := breachTxn.Copy()
		btx.Version = i

		btxid := btx.TxHash()

		localOutpoint := wire.OutPoint{
			Hash:  btxid,
			Index: 0,
		}
		remoteOutpoint := wire.OutPoint{
			Hash:  btxid,
			Index: 1,
		}

		return &lnwallet.BreachRetribution{
			BreachTransaction:    btx,
			RevokedStateNum:      uint64(i),
			KeyRing:              commitKeyRing,
			RemoteDelay:          csvDelay,
			LocalOutpoint:        localOutpoint,
			LocalOutputSignDesc:  toLocalSignDesc,
			RemoteOutpoint:       remoteOutpoint,
			RemoteOutputSignDesc: toRemoteSignDesc,
		}
	}

	const numUpdates = 5

	var hints []wtdb.BreachHint
	for i := int32(0); i < numUpdates; i++ {
		breachInfo := newBreach(i)
		breachTxID := breachInfo.BreachTransaction.TxHash()
		hints = append(hints, wtdb.NewBreachHintFromHash(&breachTxID))
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		failTimeout := time.After(3 * time.Second)
		for {
			select {
			case <-time.After(time.Second):
				matches, err := serverDB.QueryMatches(hints)
				if err != nil {
					t.Fatalf("unable to query for hints: "+
						"%v", err)
				}

				if len(matches) == len(hints) {
					return
				} else {
					fmt.Printf("received %d/%d\n", len(matches), len(hints))
				}
			case <-failTimeout:
				matches, err := serverDB.QueryMatches(hints)
				if err != nil {
					t.Fatalf("unable to query for hints: %v", err)
				}

				if len(matches) == len(hints) {
					return
				}

				t.Fatalf("breach hints not received, only got %d/%d",
					len(matches), len(hints))
			}
		}
	}()

	var chanID lnwire.ChannelID
	for i := int32(0); i < numUpdates; i++ {
		breachInfo := newBreach(i)
		err = client.BackupState(&chanID, breachInfo)
		if err != nil {
			t.Fatalf("Unable to request backup: %v", err)
		}
	}

	// Stop the client in the background, to assert the pipeline is always
	// flushed before it exits.
	go client.Stop()

	// Wait for all of the updates to be populated in the server's database.
	wg.Wait()
}

func testClientBackup(t *testing.T) {

}
