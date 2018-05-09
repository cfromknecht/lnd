package client

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

var (
	testPrivKeyBytes = []byte{
		0x2b, 0xd8, 0x06, 0xc9, 0x7f, 0x0e, 0x00, 0xaf,
		0x1a, 0x1f, 0xc3, 0x32, 0x8f, 0xa7, 0x63, 0xa9,
		0x26, 0x97, 0x23, 0xc8, 0xdb, 0x8f, 0xac, 0x4f,
		0x93, 0xaf, 0x71, 0xdb, 0x18, 0x6d, 0x6e, 0x90,
	}

	clientKeyPriv, clientKeyPub = btcec.PrivKeyFromBytes(btcec.S256(),
		testPrivKeyBytes)
)

type mockSigner struct {
	key *btcec.PrivateKey
}

func (m *mockSigner) SignOutputRaw(tx *wire.MsgTx,
	signDesc *lnwallet.SignDescriptor) ([]byte, error) {
	amt := signDesc.Output.Value
	witnessScript := signDesc.WitnessScript
	privKey := m.key

	if !privKey.PubKey().IsEqual(signDesc.PubKey) {
		return nil, fmt.Errorf("incorrect key passed")
	}

	switch {
	case signDesc.SingleTweak != nil:
		privKey = lnwallet.TweakPrivKey(privKey,
			signDesc.SingleTweak)
	case signDesc.DoubleTweak != nil:
		privKey = lnwallet.DeriveRevocationPrivKey(privKey,
			signDesc.DoubleTweak)
	}

	sig, err := txscript.RawTxInWitnessSignature(tx, signDesc.SigHashes,
		signDesc.InputIndex, amt, witnessScript, signDesc.HashType,
		privKey)
	if err != nil {
		return nil, err
	}

	return sig[:len(sig)-1], nil
}

func (m *mockSigner) ComputeInputScript(tx *wire.MsgTx,
	signDesc *lnwallet.SignDescriptor) (*lnwallet.InputScript, error) {
	witnessScript, err := txscript.WitnessSignature(tx, signDesc.SigHashes,
		signDesc.InputIndex, signDesc.Output.Value,
		signDesc.Output.PkScript, signDesc.HashType, m.key, true)
	if err != nil {
		return nil, err
	}

	return &lnwallet.InputScript{
		Witness: witnessScript,
	}, nil
}

func TestClientSignAndEncryptState(t *testing.T) {
	t.Parallel()

	signer := &mockSigner{clientKeyPriv}

	client, err := New(clientKeyPriv, signer)
	if err != nil {
		t.Fatalf("failed creating client: %v", err)
	}

	err = client.Start()
	if err != nil {
		t.Fatalf("unable to start client: %v", err)
	}

	// Create a state update. Since the client hasn't been told do watch
	// this channel yet.
	stateUpdate := &RevokedCommitment{
		ShortChanID:   1111,
		LocalBalance:  lnwire.NewMSatFromSatoshis(btcutil.Amount(1 * btcutil.SatoshiPerBitcoin)),
		RemoteBalance: lnwire.NewMSatFromSatoshis(btcutil.Amount(2 * btcutil.SatoshiPerBitcoin)),
		Height:        4,
		Revocation:    [32]byte{0xff, 0x19, 0x18},
	}

	// Create some random test basepoints
	key, _ := btcec.NewPrivateKey(btcec.S256())
	localRevocationBasePoint := key.PubKey()

	// Since the output that will be claimed is the remote's revoked
	// to_local output, we set the private key of the mockSigner to
	// be the private key corresponding to the revocation basepoint.
	signer.key = key

	key, _ = btcec.NewPrivateKey(btcec.S256())
	localDelayedBasePoint := key.PubKey()

	key, _ = btcec.NewPrivateKey(btcec.S256())
	localPaymentBasePoint := key.PubKey()

	key, _ = btcec.NewPrivateKey(btcec.S256())
	remoteKeyPub := key.PubKey()

	key, _ = btcec.NewPrivateKey(btcec.S256())
	remoteRevocationBasePoint := key.PubKey()

	key, _ = btcec.NewPrivateKey(btcec.S256())
	remoteDelayedBasePoint := key.PubKey()

	key, _ = btcec.NewPrivateKey(btcec.S256())
	remotePaymentBasePoint := key.PubKey()

	testOutputAddr := "tb1q7cd5j2dwuw32pnzrhgjgcv4zgay7nd7fcr5zjn"

	feeRate := uint64(5000)
	sweepAddr, err := btcutil.DecodeAddress(testOutputAddr, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("unable to decode address: %v", err)
	}
	outputScript, err := txscript.PayToAddrScript(sweepAddr)
	if err != nil {
		t.Fatalf("unable to create address script: %v", err)
	}

	localDustLimit := btcutil.Amount(200)
	remoteDustLimit := btcutil.Amount(1300)
	csvTimeoutLocal := uint32(5)
	csvTimeoutRemote := uint32(4)

	localCfg := &channeldb.ChannelConfig{
		ChannelConstraints: channeldb.ChannelConstraints{
			DustLimit:        localDustLimit,
			MaxPendingAmount: lnwire.MilliSatoshi(rand.Int63()),
			ChanReserve:      btcutil.Amount(rand.Int63()),
			MinHTLC:          lnwire.MilliSatoshi(rand.Int63()),
			MaxAcceptedHtlcs: uint16(rand.Int31()),
		},
		CsvDelay:            uint16(csvTimeoutLocal),
		MultiSigKey:         clientKeyPub,
		RevocationBasePoint: localRevocationBasePoint,
		PaymentBasePoint:    localPaymentBasePoint,
		DelayBasePoint:      localDelayedBasePoint,
	}

	remoteCfg := &channeldb.ChannelConfig{
		ChannelConstraints: channeldb.ChannelConstraints{
			DustLimit:        remoteDustLimit,
			MaxPendingAmount: lnwire.MilliSatoshi(rand.Int63()),
			ChanReserve:      btcutil.Amount(rand.Int63()),
			MinHTLC:          lnwire.MilliSatoshi(rand.Int63()),
			MaxAcceptedHtlcs: uint16(rand.Int31()),
		},
		CsvDelay:            uint16(csvTimeoutRemote),
		MultiSigKey:         remoteKeyPub,
		RevocationBasePoint: remoteRevocationBasePoint,
		PaymentBasePoint:    remotePaymentBasePoint,
		DelayBasePoint:      remoteDelayedBasePoint,
	}

	prevOut := &wire.OutPoint{
		Hash:  chainhash.Hash([32]byte{0x01, 0x02, 0x03}),
		Index: 0,
	}
	fundingTxIn := wire.NewTxIn(prevOut, nil, nil)

	// Update the client's known channels with this one, making it able
	// to sign and encrypt the next state.

	info := &chanInfo{
		feeRate:       feeRate,
		outputScript:  outputScript,
		localChanCfg:  localCfg,
		remoteChanCfg: remoteCfg,
		fundingTxIn:   fundingTxIn,
	}

	w := &watchSession{
		info: info,
	}
	sign, commitHash, err := client.signState(w, stateUpdate)
	if err != nil {
		t.Fatalf("signing state failed: %v", err)
	}
	fmt.Println(sign)
	fmt.Println(commitHash)

	shortChanID := uint64(1111)

	err = client.WatchChannel(shortChanID, fundingTxIn, localCfg, remoteCfg, feeRate, outputScript)
	if err != nil {
		t.Fatalf("unable to watch channel: %v", err)
	}
	fmt.Println("watch channel ok")
	remoteBtc, _ := btcutil.NewAmount(2)
	remoteMSat := lnwire.NewMSatFromSatoshis(remoteBtc)
	localBtc, _ := btcutil.NewAmount(1)
	localMSat := lnwire.NewMSatFromSatoshis(localBtc)

	rev := &RevokedCommitment{
		ShortChanID:   shortChanID,
		LocalBalance:  localMSat,
		RemoteBalance: remoteMSat,
		Height:        1000,
		Revocation:    [32]byte{1},
		DustLimit:     1000,
	}

	if err := client.QueueNewState(rev); err != nil {
		t.Fatalf("unable to queue state")
	}

	client.Stop()

}

func TestClientHandshake(t *testing.T) {
	t.Parallel()

}
