package wtclient

import (
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/txsort"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/sweep"
	"github.com/lightningnetwork/lnd/watchtower/blob"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
)

type backupTask struct {
	chanID         lnwire.ChannelID
	commitHeight   uint64
	breachInfo     *lnwallet.BreachRetribution
	breachedInputs []sweep.Input
	totalAmt       btcutil.Amount
	txWeight       int64

	sweepAmt      int64
	rewardAmt     int64
	rewardAddress []byte
	blobType      blob.Type

	justiceKit *blob.JusticeKit
}

// newBackupTask
func newBackupTask(chanID *lnwire.ChannelID,
	breachInfo *lnwallet.BreachRetribution) *backupTask {

	// Compute the set of candidate inputs, total input amount, and
	// estimated weight for the justice transaction. These will be used as
	// inputs to compute if the task can be accepted under a given session's
	// policy, as the exact split can't be determined without knowing the
	// session's negotiated reward rate, fee rate, etc.
	var (
		totalAmt       int64
		weightEstimate lnwallet.TxWeightEstimator
		breachedInputs []sweep.Input
	)

	// The valid justice transaction will always have a sweep output paying to
	// us, and a reward output paying to the tower.
	weightEstimate.AddP2WKHOutput()
	weightEstimate.AddP2WKHOutput()

	// If the to-remote output is non-dust, add it to the set of candidate
	// inputs, total input amount, and weight estimate.
	if breachInfo.RemoteOutputSignDesc != nil {
		breachedInput := sweep.MakeBaseInput(
			&breachInfo.RemoteOutpoint,
			lnwallet.CommitmentRevoke,
			breachInfo.RemoteOutputSignDesc,
			0,
		)
		breachedInputs = append(breachedInputs, &breachedInput)
		totalAmt += breachInfo.RemoteOutputSignDesc.Output.Value
		weightEstimate.AddWitnessInput(lnwallet.P2WKHWitnessSize)
	}

	// If the to-local output is non-dust, add it to the set of candidate
	// inputs, total input amount, and weight estimate.
	if breachInfo.LocalOutputSignDesc != nil {
		breachedInput := sweep.MakeBaseInput(
			&breachInfo.LocalOutpoint,
			lnwallet.CommitmentNoDelay,
			breachInfo.LocalOutputSignDesc,
			0,
		)
		breachedInputs = append(breachedInputs, &breachedInput)
		totalAmt += breachInfo.LocalOutputSignDesc.Output.Value
		weightEstimate.AddWitnessInput(lnwallet.ToLocalPenaltyWitnessSize)
	}

	return &backupTask{
		chanID:         *chanID,
		commitHeight:   breachInfo.RevokedStateNum,
		breachInfo:     breachInfo,
		breachedInputs: breachedInputs,
		totalAmt:       btcutil.Amount(totalAmt),
		txWeight:       int64(weightEstimate.Weight()),
	}
}

// assignSession
func (t *backupTask) assignSession(session *wtdb.ClientSessionInfo) error {
	// Derive the output values corresponding to the sweep and reward
	// outputs, which can be fully determined at the time the exact session
	// is known.
	var (
		sweepAmt  btcutil.Amount
		rewardAmt btcutil.Amount
		err       error
	)

	blobType := session.Policy.BlobType
	if blobType.Has(blob.FlagReward) {
		sweepAmt, rewardAmt, err = session.ComputeRewardOutputs(
			t.totalAmt, t.txWeight,
		)
		if err != nil {
			// A valid justice transaction could not be created for
			// this session, likely because either the sweep or
			// reward output resulted in dust.  This task will be
			// abandoned since it cannot satisfy the policy required
			// by the tower, or is otherwise uneconomical to backup.
			return err
		}

		// Cache the computed output values in the backup task in
		// advance of signing the final transaction to avoid recomputing
		// them. We also can set the reward address to use for the
		// tower, as this is tied to the session this task was assigned.
		t.sweepAmt = int64(sweepAmt)
		t.rewardAmt = int64(rewardAmt)
		t.rewardAddress = session.RewardAddress

	} else {
		sweepAmt, err = session.ComputeAltruistOutput(
			t.totalAmt, t.txWeight,
		)
		if err != nil {
			return err
		}
		// Cache the computed output values in the backup task in
		// advance of signing the final transaction to avoid recomputing
		// them. We also can set the reward address to use for the
		// tower, as this is tied to the session this task was assigned.
		t.sweepAmt = int64(sweepAmt)
	}

	t.blobType = session.Policy.BlobType

	return nil
}

// craftSessionPayload
func (t *backupTask) craftSessionPayload(sweepAddress []byte,
	signer lnwallet.Signer) (wtdb.BreachHint, []byte, error) {

	var hint wtdb.BreachHint

	// First, copy over the sweep address, the pubkeys used to derive the
	// to-local script, and the remote CSV delay.
	keyRing := t.breachInfo.KeyRing
	justiceKit := &blob.JusticeKit{
		SweepAddress:     sweepAddress,
		RevocationPubKey: toBlobPubKey(keyRing.RevocationKey),
		LocalDelayPubKey: toBlobPubKey(keyRing.DelayKey),
		CSVDelay:         t.breachInfo.RemoteDelay,
	}

	// If this commitment has an output that pays to us, copy the to-remote
	// pubkey into the justice kit. This serves as the indicator to the
	// tower that we expect the breaching transaction to have a non-dust
	// output to spend from.
	if t.breachInfo.LocalOutputSignDesc != nil {
		justiceKit.CommitToRemotePubKey = toBlobPubKey(
			keyRing.NoDelayKey,
		)
	}

	// Now, begin construction of the justice transaction. We'll start with
	// a version 2 transaction.
	justiceTxn := wire.NewMsgTx(2)

	// Next, add the non-dust inputs that were derived from the breach
	// information. This will either be contain both the to-local and
	// to-remote outputs, or only be the to-local output.
	for _, input := range t.breachedInputs {
		justiceTxn.AddTxIn(&wire.TxIn{
			PreviousOutPoint: *input.OutPoint(),
		})
	}

	if t.blobType.Has(blob.FlagReward) {
		// Add the sweep output and reward outputs, as we have already
		// checked that they were both non-dusty.
		justiceTxn.AddTxOut(&wire.TxOut{
			Value:    t.sweepAmt,
			PkScript: sweepAddress,
		})
		justiceTxn.AddTxOut(&wire.TxOut{
			Value:    t.rewardAmt,
			PkScript: t.rewardAddress,
		})
	} else {
		// Add the sweep output output, which is already verified to be
		// non-dust.
		justiceTxn.AddTxOut(&wire.TxOut{
			Value:    t.sweepAmt,
			PkScript: sweepAddress,
		})
	}

	// Sort the justice transaction according to BIP69.
	txsort.InPlaceSort(justiceTxn)

	// Check that the justice transaction meets basic validity requirements
	// before attempting to attach the witnesses.
	btx := btcutil.NewTx(justiceTxn)
	if err := blockchain.CheckTransactionSanity(btx); err != nil {
		return hint, nil, err
	}

	log.Debugf("justice txn: %v", spew.Sdump(justiceTxn))

	// Construct a sighash cache to improve signing performance.
	hashCache := txscript.NewTxSigHashes(justiceTxn)

	// Since the transaction inputs could have been reordered as a result of
	// the BIP69 sort, create an index mapping each prevout to it's new
	// index.
	inputIndex := make(map[wire.OutPoint]int)
	for i, txIn := range justiceTxn.TxIn {
		inputIndex[txIn.PreviousOutPoint] = i
	}

	// Now, iterate through the list of inputs that were initially added to
	// the transaction and store the computed witness within the justice
	// kit.
	for _, input := range t.breachedInputs {
		// Lookup the input's new post-sort position.
		i := inputIndex[*input.OutPoint()]

		// Construct the full witness required to spend this input.
		witness, err := input.BuildWitness(
			signer, justiceTxn, hashCache, i,
		)
		if err != nil {
			return hint, nil, err
		}

		// Parse the DER-encoded signature from the first position of
		// the resulting witness. We trim an extra byte to remove the
		// sighash flag.
		rawSignature := witness[0][:len(witness[0])-1]

		// Reencode the DER signature into a fixed-size 64 byte
		// signature.
		signature, err := lnwire.NewSigFromRawSignature(rawSignature)
		if err != nil {
			return hint, nil, err
		}

		// Finally, copy the serialized signature into the justice kit,
		// using the input's witness type to select the appropriate
		// field.
		switch input.WitnessType() {
		case lnwallet.CommitmentRevoke:
			copy(justiceKit.CommitToLocalSig[:], signature[:])

		case lnwallet.CommitmentNoDelay:
			copy(justiceKit.CommitToRemoteSig[:], signature[:])
		}
	}

	// Compute the breach hint from the breach transaction id's prefix.
	breachKey := t.breachInfo.BreachTransaction.TxHash()
	hint = wtdb.NewBreachHintFromHash(&breachKey)

	// Finally, encrypt the computed justice kit using the full breach
	// transaction id, which will allow the tower to recover the contents
	// after the transaction is seen in the chain or mempool.
	encBlob, err := justiceKit.Encrypt(breachKey[:], t.blobType)
	if err != nil {
		return hint, nil, err
	}

	return hint, encBlob, nil
}

func toBlobPubKey(pubKey *btcec.PublicKey) blob.PubKey {
	var blobPubKey blob.PubKey
	copy(blobPubKey[:], pubKey.SerializeCompressed())
	return blobPubKey
}
