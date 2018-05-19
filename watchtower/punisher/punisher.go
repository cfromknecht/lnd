package punisher

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/watchtower/sweep"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/roasbeef/btcd/blockchain"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

var (
	ErrOutputNotFound = errors.New("unable to find output on commit tx")
)

type PunishInfo struct {
	BreachedCommitmentTx  *wire.MsgTx
	SessionInfo           *wtdb.SessionInfo
	Descriptor            *sweep.Descriptor
	RevocationBasePoint   *btcec.PublicKey
	LocalDelayedBasePoint *btcec.PublicKey
	CsvDelay              uint16
	FeeRate               lnwallet.SatPerVByte
	OutputScript          []byte
	TowerReward           uint64
	TowerOutputScript     []byte
	Revocation            [32]byte
	PenaltySignature      lnwire.Sig
}

type Config struct {
	ChainParams     *chaincfg.Params
	SendTransaction func(*wire.MsgTx) error
}

type Punisher interface {
	Punish(*PunishInfo) error
}

type punisher struct {
	cfg *Config
}

func New(cfg *Config) (*punisher, error) {
	p := &punisher{
		cfg: cfg,
	}

	return p, nil
}

func (p *punisher) Punish(info *PunishInfo) error {
	penaltyTx, remotePkScript, err := AssemblePenaltyTx(info.BreachedCommitmentTx,
		info.RevocationBasePoint, info.LocalDelayedBasePoint,
		info.CsvDelay, info.FeeRate, info.TowerReward,
		info.OutputScript, info.TowerOutputScript,
		info.Revocation)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println(penaltyTx)
	fmt.Println(remotePkScript)

	sig := info.PenaltySignature[:]
	witnessStack := wire.TxWitness(make([][]byte, 3))
	witnessStack[0] = append(sig, byte(txscript.SigHashSingle))
	witnessStack[1] = []byte{1}
	witnessStack[2] = remotePkScript

	remoteWitnessHash, err := lnwallet.WitnessScriptHash(remotePkScript)
	if err != nil {
		return err
	}
	var remoteAmt btcutil.Amount
	for _, txOut := range info.BreachedCommitmentTx.TxOut {
		switch {
		case bytes.Equal(txOut.PkScript, remoteWitnessHash):
			remoteAmt = btcutil.Amount(txOut.Value)
		}
	}
	flags := txscript.StandardVerifyFlags
	vm, err := txscript.NewEngine(
		remoteWitnessHash, penaltyTx, 0, flags,
		nil, nil, int64(remoteAmt))
	if err != nil {
		return err
	}
	if err := vm.Execute(); err != nil {
		return err
	}

	return p.cfg.SendTransaction(penaltyTx)
}

func assemblePenaltyTx(info *PunishInfo) (*wire.MsgTx, error) {
	sweepDesc := info.Descriptor

	revocationPubKey, err := btcec.ParsePubKey(
		sweepDesc.Params.RevocationPubKey[:], btcec.S256(),
	)
	if err != nil {
		return nil, err
	}

	localDelayedPubKey, err := btcec.ParsePubKey(
		sweepDesc.Params.LocalDelayPubKey[:], btcec.S256(),
	)
	if err != nil {
		return nil, err
	}

	toLocalScript, err := lnwallet.CommitScriptToSelf(
		localDelayedPubKey, revocationPubKey, sweepDesc.Params.CSVDelay,
	)
	if err != nil {
		return nil, err
	}

	toLocalWitnessHash, err := lnwallet.WitnessScriptHash(toLocalScript)
	if err != nil {
		return nil, err
	}

	commitHash := info.BreachedCommitmentTx.TxHash()

	toLocalIndex, toLocalTxOut, err := findTxOutByPkScript(
		info.BreachedCommitmentTx, toLocalWitnessHash,
	)
	if err != nil {
		return nil, err
	}

	toLocalOutPoint := wire.OutPoint{
		Hash:  commitHash,
		Index: toLocalIndex,
	}

	var (
		penaltyTxn     = wire.NewMsgTx(2)
		weightEstimate lnwallet.TxWeightEstimator
		totalInputs    int64
	)

	penaltyTxn.AddTxIn(&wire.TxIn{
		PreviousOutPoint: toLocalOutPoint,
	})
	weightEstimate.AddWitnessInput(lnwallet.ToLocalPenaltyWitnessSize)
	totalInputs += toLocalTxOut.Value

	if info.Descriptor.HasP2WKHOutput {
		p2wkh160 := btcutil.Hash160(sweepDesc.Params.P2WKHPubKey[:])
		p2wkhScript := append([]byte{0}, p2wkh160...)

		p2wkhIndex, p2wkhTxOut, err := findTxOutByPkScript(
			info.BreachedCommitmentTx, p2wkhScript,
		)
		if err != nil {
			return nil, err
		}

		p2wkhOutPoint := wire.OutPoint{
			Hash:  commitHash,
			Index: p2wkhIndex,
		}

		penaltyTxn.AddTxIn(&wire.TxIn{
			PreviousOutPoint: p2wkhOutPoint,
		})
		weightEstimate.AddWitnessInput(lnwallet.P2WKHWitnessSize)
		totalInputs += p2wkhTxOut.Value
	}

	weightEstimate.AddP2WKHOutput()
	weightEstimate.AddP2WKHOutput()

	txVSize := int64(weightEstimate.VSize())

	penaltyTxn.AddTxOut(&wire.TxOut{
		PkScript: info.SessionInfo.RewardAddress,
		Value:    toLocalTxOut.Value,
	})

	penaltyTxn.AddTxOut(&wire.TxOut{
		PkScript: info.SessionInfo.SweepAddress,
		Value:    p2wkhTxOut.Value,
	})
}

func findTxOutByPkScript(txn *wire.MsgTx,
	pkScript []byte) (uint32, *wire.TxOut, error) {

	found, index := lnwallet.FindScriptOutputIndex(txn, pkScript)
	if !found {
		return 0, nil, ErrOutputNotFound
	}

	return index, txn.TxOut[index], nil
}

func AssemblePenaltyTx(commitTx *wire.MsgTx, localRevocationBasePoint,
	remoteDelayBasePoint *btcec.PublicKey, remoteCsvDelay uint16,
	feeRate lnwallet.SatPerVByte, towerReward uint64,
	outputScript, towerOutputScript []byte,
	revocation [32]byte) (*wire.MsgTx, []byte, error) {

	_, commitmentPoint := btcec.PrivKeyFromBytes(btcec.S256(),
		revocation[:])

	revocationKey := lnwallet.DeriveRevocationPubkey(localRevocationBasePoint, commitmentPoint)
	localDelayedKey := lnwallet.TweakPubKey(remoteDelayBasePoint, commitmentPoint)

	commitHash := commitTx.TxHash()
	fmt.Println("commithash is at this point", hex.EncodeToString(commitHash[:]))

	// Next, reconstruct the scripts as they were present at this state
	// number so we can have the proper witness script to sign and include
	// within the final witness.
	remoteDelay := uint32(remoteCsvDelay)
	remotePkScript, err := lnwallet.CommitScriptToSelf(remoteDelay, localDelayedKey,
		revocationKey)
	if err != nil {
		return nil, nil, err
	}
	remoteWitnessHash, err := lnwallet.WitnessScriptHash(remotePkScript)
	if err != nil {
		return nil, nil, err
	}

	// In order to fully populate the breach retribution struct, we'll need
	// to find the exact index of the local+remote commitment outputs.
	remoteOutpoint := wire.OutPoint{
		Hash: commitHash,
	}
	var remoteAmt btcutil.Amount
	for i, txOut := range commitTx.TxOut {
		switch {
		case bytes.Equal(txOut.PkScript, remoteWitnessHash):
			remoteOutpoint.Index = uint32(i)
			remoteAmt = btcutil.Amount(txOut.Value)
		}
	}
	penaltyTx := wire.NewMsgTx(2)
	penaltyTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: remoteOutpoint,
	})

	// The watchttower should get part of the sweeped value.
	towerOutputValue := uint64(remoteAmt) * towerReward / 1000
	penaltyTx.AddTxOut(&wire.TxOut{
		PkScript: towerOutputScript,
		Value:    int64(towerOutputValue),
	})

	penaltyTx.AddTxOut(&wire.TxOut{
		PkScript: outputScript,
		Value:    0, // This will be set after fee is calculated.
	})
	btx := btcutil.NewTx(penaltyTx)
	txWeight := blockchain.GetTransactionWeight(btx)
	estimator := &lnwallet.StaticFeeEstimator{
		FeeRate: lnwallet.SatPerVByte(feeRate),
	}
	feePerVSize, err := estimator.EstimateFeePerVSize(1)
	if err != nil {
		return nil, nil, err
	}
	fee := txWeight * int64(1000*feePerVSize) / 1000
	penaltyTx.TxOut[1].Value = int64(remoteAmt) - int64(towerOutputValue) - fee
	fmt.Println("remote:", uint64(remoteAmt))
	fmt.Println("tower:", towerReward)
	fmt.Println("fee:", fee)

	btx = btcutil.NewTx(penaltyTx)
	fmt.Println("check sanit")
	if err := blockchain.CheckTransactionSanity(btx); err != nil {
		fmt.Println("not sane:", err)
		return nil, nil, err
	}

	return penaltyTx, remotePkScript, nil
}
