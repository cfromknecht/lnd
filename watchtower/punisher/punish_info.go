package punisher

import (
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/watchtower/sweep"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
)

type PunishInfo struct {
	BreachedCommitmentTx *wire.MsgTx
	SessionInfo          *wtdb.SessionInfo
	Descriptor           *sweep.Descriptor
}

func (p *PunishInfo) CommitToLocalInput() (*sweep.ToLocalInput, error) {
	toLocalScript, err := p.Descriptor.CommitToLocalScript()
	if err != nil {
		return nil, err
	}

	toLocalWitnessHash, err := lnwallet.WitnessScriptHash(toLocalScript)
	if err != nil {
		return nil, err
	}

	toLocalIndex, toLocalTxOut, err := findTxOutByPkScript(
		p.BreachedCommitmentTx, toLocalWitnessHash,
	)
	if err != nil {
		return nil, err
	}

	commitHash := p.BreachedCommitmentTx.TxHash()

	toLocalInput := &sweep.ToLocalInput{
		Value: btcutil.Amount(toLocalTxOut.Value),
		PrevOutPoint: wire.OutPoint{
			Hash:  commitHash,
			Index: toLocalIndex,
		},
		OutputScript: toLocalScript,
	}

	return toLocalInput, nil
}

func (p *PunishInfo) CommitP2WKHInput() (*sweep.P2WKHInput, error) {
	p2wkhScript := p.Descriptor.CommitP2WKHScript()

	p2wkhIndex, p2wkhTxOut, err := findTxOutByPkScript(
		p.BreachedCommitmentTx, p2wkhScript,
	)
	if err != nil {
		return nil, err
	}

	commitHash := p.BreachedCommitmentTx.TxHash()

	p2wkhInput := &sweep.P2WKHInput{
		Value: btcutil.Amount(p2wkhTxOut.Value),
		PrevOutPoint: wire.OutPoint{
			Hash:  commitHash,
			Index: p2wkhIndex,
		},
		OutputScript: p2wkhScript,
	}

	return p2wkhInput, nil
}

func (p *PunishInfo) CreatePenaltyTx() (*wire.MsgTx, error) {
	var (
		sweepInputs    = make([]sweep.Input, 0, 2)
		weightEstimate lnwallet.TxWeightEstimator
	)

	weightEstimate.AddP2WKHOutput()
	weightEstimate.AddP2WKHOutput()

	toLocalInput, err := p.CommitToLocalInput()
	if err != nil {
		return nil, err
	}

	weightEstimate.AddWitnessInput(lnwallet.ToLocalPenaltyWitnessSize)
	sweepInputs = append(sweepInputs, toLocalInput)

	if p.Descriptor.HasP2WKHOutput {
		p2wkhInput, err := p.CommitP2WKHInput()
		if err != nil {
			return nil, err
		}

		weightEstimate.AddWitnessInput(lnwallet.P2WKHWitnessSize)
		sweepInputs = append(sweepInputs, p2wkhInput)
	}

	// TODO(conner): sweep htlc outputs

	txVSize := int64(weightEstimate.VSize())

	return p.assemblePenaltyTx(txVSize, sweepInputs...)
}

func (p *PunishInfo) assemblePenaltyTx(txVSize int64,
	inputs ...sweep.Input) (*wire.MsgTx, error) {

	penaltyTxn := wire.NewMsgTx(2)

	var totalAmt btcutil.Amount
	for _, input := range inputs {
		totalAmt += input.Amount()
		penaltyTxn.AddTxIn(&wire.TxIn{
			PreviousOutPoint: input.OutPoint(),
		})
	}

	sweepAmt, rewardAmt, err := p.SessionInfo.ComputeSweepOutputs(
		totalAmt, txVSize,
	)
	if err != nil {
		return nil, err
	}

	penaltyTxn.AddTxOut(&wire.TxOut{
		PkScript: p.SessionInfo.SweepAddress,
		Value:    int64(sweepAmt),
	})
	penaltyTxn.AddTxOut(&wire.TxOut{
		PkScript: p.SessionInfo.RewardAddress,
		Value:    int64(rewardAmt),
	})

	for i, input := range inputs {
		penaltyTxn.TxIn[i].Witness = input.BuildWitness()
	}

	return penaltyTxn, nil
}

func findTxOutByPkScript(txn *wire.MsgTx,
	pkScript []byte) (uint32, *wire.TxOut, error) {

	found, index := lnwallet.FindScriptOutputIndex(txn, pkScript)
	if !found {
		return 0, nil, ErrOutputNotFound
	}

	return index, txn.TxOut[index], nil
}
