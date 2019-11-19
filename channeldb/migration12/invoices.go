package migration12

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// MaxMemoSize is maximum size of the memo field within invoices stored
	// in the database.
	MaxMemoSize = 1024

	// maxReceiptSize is the maximum size of the payment receipt stored
	// within the database along side incoming/outgoing invoices.
	maxReceiptSize = 1024

	// MaxPaymentRequestSize is the max size of a payment request for
	// this invoice.
	// TODO(halseth): determine the max length payment request when field
	// lengths are final.
	MaxPaymentRequestSize = 4096

	// A set of tlv type definitions used to serialize invoice htlcs to the
	// database.
	//
	// NOTE: A migration should be added whenever this list changes. This
	// prevents against the database being rolled back to an older
	// format where the surrounding logic might assume a different set of
	// fields are known.
	chanIDType       tlv.Type = 1
	htlcIDType       tlv.Type = 3
	amtType          tlv.Type = 5
	acceptHeightType tlv.Type = 7
	acceptTimeType   tlv.Type = 9
	resolveTimeType  tlv.Type = 11
	expiryHeightType tlv.Type = 13
	htlcStateType    tlv.Type = 15

	// A set of tlv type definitions used to serialie invoice bodies.
	//
	// NOTE: A migration should be added whenever this list changes. This
	// prevents against the database being rolled back to an older
	// format where the surrounding logic might assume a different set of
	// fields are known.
	memoType        tlv.Type = 0
	payReqType      tlv.Type = 1
	createTimeType  tlv.Type = 2
	settleTimeType  tlv.Type = 3
	addIndexType    tlv.Type = 4
	settleIndexType tlv.Type = 5
	preimageType    tlv.Type = 6
	valueType       tlv.Type = 7
	cltvDeltaType   tlv.Type = 8
	expiryType      tlv.Type = 9
	paymentAddrType tlv.Type = 10
	featuresType    tlv.Type = 11
	invStateType    tlv.Type = 12
	amtPaidType     tlv.Type = 13
)

var (

	// ErrInvalidCircuitKeyLen signals that a circuit key could not be
	// decoded because the byte slice is of an invalid length.
	ErrInvalidCircuitKeyLen = fmt.Errorf(
		"length of serialized circuit key must be 16 bytes")

	// invoiceBucket is the name of the bucket within the database that
	// stores all data related to invoices no matter their final state.
	// Within the invoice bucket, each invoice is keyed by its invoice ID
	// which is a monotonically increasing uint32.
	invoiceBucket = []byte("invoices")

	// Big endian is the preferred byte order, due to cursor scans over
	// integer keys iterating in order.
	byteOrder = binary.BigEndian
)

// CircuitKey is used by a channel to uniquely identify the HTLCs it receives
// from the switch, and is used to purge our in-memory state of HTLCs that have
// already been processed by a link. Two list of CircuitKeys are included in
// each CommitDiff to allow a link to determine which in-memory htlcs directed
// the opening and closing of circuits in the switch's circuit map.
type CircuitKey struct {
	// ChanID is the short chanid indicating the HTLC's origin.
	//
	// NOTE: It is fine for this value to be blank, as this indicates a
	// locally-sourced payment.
	ChanID lnwire.ShortChannelID

	// HtlcID is the unique htlc index predominately assigned by links,
	// though can also be assigned by switch in the case of locally-sourced
	// payments.
	HtlcID uint64
}

// SetBytes deserializes the given bytes into this CircuitKey.
func (k *CircuitKey) SetBytes(bs []byte) error {
	if len(bs) != 16 {
		return ErrInvalidCircuitKeyLen
	}

	k.ChanID = lnwire.NewShortChanIDFromInt(
		binary.BigEndian.Uint64(bs[:8]))
	k.HtlcID = binary.BigEndian.Uint64(bs[8:])

	return nil
}

// Bytes returns the serialized bytes for this circuit key.
func (k CircuitKey) Bytes() []byte {
	var bs = make([]byte, 16)
	binary.BigEndian.PutUint64(bs[:8], k.ChanID.ToUint64())
	binary.BigEndian.PutUint64(bs[8:], k.HtlcID)
	return bs
}

// Encode writes a CircuitKey to the provided io.Writer.
func (k *CircuitKey) Encode(w io.Writer) error {
	var scratch [16]byte
	binary.BigEndian.PutUint64(scratch[:8], k.ChanID.ToUint64())
	binary.BigEndian.PutUint64(scratch[8:], k.HtlcID)

	_, err := w.Write(scratch[:])
	return err
}

// Decode reads a CircuitKey from the provided io.Reader.
func (k *CircuitKey) Decode(r io.Reader) error {
	var scratch [16]byte

	if _, err := io.ReadFull(r, scratch[:]); err != nil {
		return err
	}
	k.ChanID = lnwire.NewShortChanIDFromInt(
		binary.BigEndian.Uint64(scratch[:8]))
	k.HtlcID = binary.BigEndian.Uint64(scratch[8:])

	return nil
}

// String returns a string representation of the CircuitKey.
func (k CircuitKey) String() string {
	return fmt.Sprintf("(Chan ID=%s, HTLC ID=%d)", k.ChanID, k.HtlcID)
}

// ContractState describes the state the invoice is in.
type ContractState uint8

const (
	// ContractOpen means the invoice has only been created.
	ContractOpen ContractState = 0

	// ContractSettled means the htlc is settled and the invoice has been
	// paid.
	ContractSettled ContractState = 1

	// ContractCanceled means the invoice has been canceled.
	ContractCanceled ContractState = 2

	// ContractAccepted means the HTLC has been accepted but not settled
	// yet.
	ContractAccepted ContractState = 3
)

// String returns a human readable identifier for the ContractState type.
func (c ContractState) String() string {
	switch c {
	case ContractOpen:
		return "Open"
	case ContractSettled:
		return "Settled"
	case ContractCanceled:
		return "Canceled"
	case ContractAccepted:
		return "Accepted"
	}

	return "Unknown"
}

// HtlcState defines the states an htlc paying to an invoice can be in.
type HtlcState uint8

// ContractTerm is a companion struct to the Invoice struct. This struct houses
// the necessary conditions required before the invoice can be considered fully
// settled by the payee.
type ContractTerm struct {
	// PaymentPreimage is the preimage which is to be revealed in the
	// occasion that an HTLC paying to the hash of this preimage is
	// extended.
	PaymentPreimage lntypes.Preimage

	// Value is the expected amount of milli-satoshis to be paid to an HTLC
	// which can be satisfied by the above preimage.
	Value lnwire.MilliSatoshi

	// FinalCltvDelta is the minimum required number of blocks before htlc
	// expiry when the invoice is accepted.
	FinalCltvDelta int32

	// Expiry defines how long after creation this invoice should expire.
	Expiry time.Duration

	// PaymentAddr is a randomly generated value include in the MPP record
	// by the sender to prevent probing of the receiver.
	PaymentAddr [32]byte

	// Features is the feature vectors advertised on the payment request.
	Features *lnwire.FeatureVector
}

// InvoiceHTLC contains details about an htlc paying to this invoice.
type InvoiceHTLC struct {
	// Amt is the amount that is carried by this htlc.
	Amt lnwire.MilliSatoshi

	// AcceptHeight is the block height at which the invoice registry
	// decided to accept this htlc as a payment to the invoice. At this
	// height, the invoice cltv delay must have been met.
	AcceptHeight uint32

	// AcceptTime is the wall clock time at which the invoice registry
	// decided to accept the htlc.
	AcceptTime time.Time

	// ResolveTime is the wall clock time at which the invoice registry
	// decided to settle the htlc.
	ResolveTime time.Time

	// Expiry is the expiry height of this htlc.
	Expiry uint32

	// State indicates the state the invoice htlc is currently in. A
	// canceled htlc isn't just removed from the invoice htlcs map, because
	// we need AcceptHeight to properly cancel the htlc back.
	State HtlcState
}

// Invoice is a payment invoice generated by a payee in order to request
// payment for some good or service. The inclusion of invoices within Lightning
// creates a payment work flow for merchants very similar to that of the
// existing financial system within PayPal, etc.  Invoices are added to the
// database when a payment is requested, then can be settled manually once the
// payment is received at the upper layer. For record keeping purposes,
// invoices are never deleted from the database, instead a bit is toggled
// denoting the invoice has been fully settled. Within the database, all
// invoices must have a unique payment hash which is generated by taking the
// sha256 of the payment preimage.
type Invoice struct {
	// Memo is an optional memo to be stored along side an invoice.  The
	// memo may contain further details pertaining to the invoice itself,
	// or any other message which fits within the size constraints.
	Memo []byte

	// PaymentRequest is an optional field where a payment request created
	// for this invoice can be stored.
	PaymentRequest []byte

	// CreationDate is the exact time the invoice was created.
	CreationDate time.Time

	// SettleDate is the exact time the invoice was settled.
	SettleDate time.Time

	// Terms are the contractual payment terms of the invoice. Once all the
	// terms have been satisfied by the payer, then the invoice can be
	// considered fully fulfilled.
	//
	// TODO(roasbeef): later allow for multiple terms to fulfill the final
	// invoice: payment fragmentation, etc.
	Terms ContractTerm

	// AddIndex is an auto-incrementing integer that acts as a
	// monotonically increasing sequence number for all invoices created.
	// Clients can then use this field as a "checkpoint" of sorts when
	// implementing a streaming RPC to notify consumers of instances where
	// an invoice has been added before they re-connected.
	//
	// NOTE: This index starts at 1.
	AddIndex uint64

	// SettleIndex is an auto-incrementing integer that acts as a
	// monotonically increasing sequence number for all settled invoices.
	// Clients can then use this field as a "checkpoint" of sorts when
	// implementing a streaming RPC to notify consumers of instances where
	// an invoice has been settled before they re-connected.
	//
	// NOTE: This index starts at 1.
	SettleIndex uint64

	// AmtPaid is the final amount that we ultimately accepted for pay for
	// this invoice. We specify this value independently as it's possible
	// that the invoice originally didn't specify an amount, or the sender
	// overpaid.
	AmtPaid lnwire.MilliSatoshi

	// State describes the state the invoice is in.
	State ContractState

	// Htlcs records all htlcs that paid to this invoice. Some of these
	// htlcs may have been marked as canceled.
	Htlcs map[CircuitKey]*InvoiceHTLC
}

// SerializeInvoice serializes an invoice to a writer.
//
// Note: this function is in use for a migration. Before making changes that
// would modify the on disk format, make a copy of the original code and store
// it with the migration.
func SerializeInvoice(w io.Writer, i *Invoice) error {
	creationDateBytes, err := i.CreationDate.MarshalBinary()
	if err != nil {
		return err
	}

	settleDateBytes, err := i.SettleDate.MarshalBinary()
	if err != nil {
		return err
	}

	var fb bytes.Buffer
	err = i.Terms.Features.EncodeBase256(&fb)
	if err != nil {
		return err
	}
	featureBytes := fb.Bytes()

	preimage := [32]byte(i.Terms.PaymentPreimage)
	value := uint64(i.Terms.Value)
	cltvDelta := uint32(i.Terms.FinalCltvDelta)
	expiry := uint64(i.Terms.Expiry)

	amtPaid := uint64(i.AmtPaid)
	state := uint8(i.State)

	tlvStream, err := tlv.NewStream(
		// Memo and payreq.
		tlv.MakePrimitiveRecord(memoType, &i.Memo),
		tlv.MakePrimitiveRecord(payReqType, &i.PaymentRequest),

		// Add/settle metadata.
		tlv.MakePrimitiveRecord(createTimeType, &creationDateBytes),
		tlv.MakePrimitiveRecord(settleTimeType, &settleDateBytes),
		tlv.MakePrimitiveRecord(addIndexType, &i.AddIndex),
		tlv.MakePrimitiveRecord(settleIndexType, &i.SettleIndex),

		// Terms.
		tlv.MakePrimitiveRecord(preimageType, &preimage),
		tlv.MakePrimitiveRecord(valueType, &value),
		tlv.MakePrimitiveRecord(cltvDeltaType, &cltvDelta),
		tlv.MakePrimitiveRecord(expiryType, &expiry),
		tlv.MakePrimitiveRecord(paymentAddrType, &i.Terms.PaymentAddr),
		tlv.MakePrimitiveRecord(featuresType, &featureBytes),

		// Invoice state.
		tlv.MakePrimitiveRecord(invStateType, &state),
		tlv.MakePrimitiveRecord(amtPaidType, &amtPaid),
	)
	if err != nil {
		return err
	}

	var b bytes.Buffer
	if err = tlvStream.Encode(&b); err != nil {
		return err
	}

	err = binary.Write(w, byteOrder, uint64(b.Len()))
	if err != nil {
		return err
	}

	if _, err = w.Write(b.Bytes()); err != nil {
		return err
	}

	return serializeHtlcs(w, i.Htlcs)
}

// serializeHtlcs serializes a map containing circuit keys and invoice htlcs to
// a writer.
//
// nolint: dupl
func serializeHtlcs(w io.Writer, htlcs map[CircuitKey]*InvoiceHTLC) error {
	for key, htlc := range htlcs {
		// Encode the htlc in a tlv stream.
		chanID := key.ChanID.ToUint64()
		amt := uint64(htlc.Amt)
		acceptTime := uint64(htlc.AcceptTime.UnixNano())
		resolveTime := uint64(htlc.ResolveTime.UnixNano())
		state := uint8(htlc.State)

		tlvStream, err := tlv.NewStream(
			tlv.MakePrimitiveRecord(chanIDType, &chanID),
			tlv.MakePrimitiveRecord(htlcIDType, &key.HtlcID),
			tlv.MakePrimitiveRecord(amtType, &amt),
			tlv.MakePrimitiveRecord(
				acceptHeightType, &htlc.AcceptHeight,
			),
			tlv.MakePrimitiveRecord(acceptTimeType, &acceptTime),
			tlv.MakePrimitiveRecord(resolveTimeType, &resolveTime),
			tlv.MakePrimitiveRecord(expiryHeightType, &htlc.Expiry),
			tlv.MakePrimitiveRecord(htlcStateType, &state),
		)
		if err != nil {
			return err
		}

		var b bytes.Buffer
		if err := tlvStream.Encode(&b); err != nil {
			return err
		}

		// Write the length of the tlv stream followed by the stream
		// bytes.
		err = binary.Write(w, byteOrder, uint64(b.Len()))
		if err != nil {
			return err
		}

		if _, err := w.Write(b.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

func DeserializeInvoice(r io.Reader) (Invoice, error) {
	var (
		preimage  [32]byte
		value     uint64
		cltvDelta uint32
		expiry    uint64
		amtPaid   uint64
		state     uint8

		creationDateBytes []byte
		settleDateBytes   []byte
		featureBytes      []byte
	)

	var i Invoice
	tlvStream, err := tlv.NewStream(
		// Memo and payreq.
		tlv.MakePrimitiveRecord(memoType, &i.Memo),
		tlv.MakePrimitiveRecord(payReqType, &i.PaymentRequest),

		// Add/settle metadata.
		tlv.MakePrimitiveRecord(createTimeType, &creationDateBytes),
		tlv.MakePrimitiveRecord(settleTimeType, &settleDateBytes),
		tlv.MakePrimitiveRecord(addIndexType, &i.AddIndex),
		tlv.MakePrimitiveRecord(settleIndexType, &i.SettleIndex),

		// Terms.
		tlv.MakePrimitiveRecord(preimageType, &preimage),
		tlv.MakePrimitiveRecord(valueType, &value),
		tlv.MakePrimitiveRecord(cltvDeltaType, &cltvDelta),
		tlv.MakePrimitiveRecord(expiryType, &expiry),
		tlv.MakePrimitiveRecord(paymentAddrType, &i.Terms.PaymentAddr),
		tlv.MakePrimitiveRecord(featuresType, &featureBytes),

		// Invoice state.
		tlv.MakePrimitiveRecord(invStateType, &state),
		tlv.MakePrimitiveRecord(amtPaidType, &amtPaid),
	)
	if err != nil {
		return i, err
	}

	var bodyLen int64
	err = binary.Read(r, byteOrder, &bodyLen)
	if err != nil {
		return i, err
	}

	lr := io.LimitReader(r, bodyLen)
	if err = tlvStream.Decode(lr); err != nil {
		return i, err
	}

	i.Terms.PaymentPreimage = lntypes.Preimage(preimage)
	i.Terms.Value = lnwire.MilliSatoshi(value)
	i.Terms.FinalCltvDelta = int32(cltvDelta)
	i.Terms.Expiry = time.Duration(expiry)
	i.AmtPaid = lnwire.MilliSatoshi(amtPaid)
	i.State = ContractState(state)

	err = i.CreationDate.UnmarshalBinary(creationDateBytes)
	if err != nil {
		return i, err
	}

	err = i.SettleDate.UnmarshalBinary(settleDateBytes)
	if err != nil {
		return i, err
	}

	rawFeatures := lnwire.NewRawFeatureVector()
	err = rawFeatures.DecodeBase256(
		bytes.NewReader(featureBytes), len(featureBytes),
	)
	if err != nil {
		return i, err
	}

	i.Terms.Features = lnwire.NewFeatureVector(
		rawFeatures, lnwire.Features,
	)

	i.Htlcs, err = deserializeHtlcs(r)
	return i, err
}

func LegacyDeserializeInvoice(r io.Reader) (Invoice, error) {
	var err error
	invoice := Invoice{}

	// TODO(roasbeef): use read full everywhere
	invoice.Memo, err = wire.ReadVarBytes(r, 0, MaxMemoSize, "")
	if err != nil {
		return invoice, err
	}
	_, err = wire.ReadVarBytes(r, 0, maxReceiptSize, "")
	if err != nil {
		return invoice, err
	}

	invoice.PaymentRequest, err = wire.ReadVarBytes(r, 0, MaxPaymentRequestSize, "")
	if err != nil {
		return invoice, err
	}

	err = binary.Read(r, byteOrder, &invoice.Terms.FinalCltvDelta)
	if err != nil {
		return invoice, err
	}

	var expiry int64
	if err := binary.Read(r, byteOrder, &expiry); err != nil {
		return invoice, err
	}
	invoice.Terms.Expiry = time.Duration(expiry)

	birthBytes, err := wire.ReadVarBytes(r, 0, 300, "birth")
	if err != nil {
		return invoice, err
	}
	if err := invoice.CreationDate.UnmarshalBinary(birthBytes); err != nil {
		return invoice, err
	}

	settledBytes, err := wire.ReadVarBytes(r, 0, 300, "settled")
	if err != nil {
		return invoice, err
	}
	if err := invoice.SettleDate.UnmarshalBinary(settledBytes); err != nil {
		return invoice, err
	}

	if _, err := io.ReadFull(r, invoice.Terms.PaymentPreimage[:]); err != nil {
		return invoice, err
	}
	var scratch [8]byte
	if _, err := io.ReadFull(r, scratch[:]); err != nil {
		return invoice, err
	}
	invoice.Terms.Value = lnwire.MilliSatoshi(byteOrder.Uint64(scratch[:]))

	if err := binary.Read(r, byteOrder, &invoice.State); err != nil {
		return invoice, err
	}

	if err := binary.Read(r, byteOrder, &invoice.AddIndex); err != nil {
		return invoice, err
	}
	if err := binary.Read(r, byteOrder, &invoice.SettleIndex); err != nil {
		return invoice, err
	}
	if err := binary.Read(r, byteOrder, &invoice.AmtPaid); err != nil {
		return invoice, err
	}

	invoice.Htlcs, err = deserializeHtlcs(r)
	if err != nil {
		return Invoice{}, err
	}

	return invoice, nil
}

// deserializeHtlcs reads a list of invoice htlcs from a reader and returns it
// as a map.
func deserializeHtlcs(r io.Reader) (map[CircuitKey]*InvoiceHTLC, error) {
	htlcs := make(map[CircuitKey]*InvoiceHTLC)

	for {
		// Read the length of the tlv stream for this htlc.
		var streamLen int64
		if err := binary.Read(r, byteOrder, &streamLen); err != nil {
			if err == io.EOF {
				break
			}

			return nil, err
		}

		htlcReader := io.LimitReader(r, streamLen)

		// Decode the contents into the htlc fields.
		var (
			htlc                    InvoiceHTLC
			key                     CircuitKey
			chanID                  uint64
			state                   uint8
			acceptTime, resolveTime uint64
			amt                     uint64
		)
		tlvStream, err := tlv.NewStream(
			tlv.MakePrimitiveRecord(chanIDType, &chanID),
			tlv.MakePrimitiveRecord(htlcIDType, &key.HtlcID),
			tlv.MakePrimitiveRecord(amtType, &amt),
			tlv.MakePrimitiveRecord(
				acceptHeightType, &htlc.AcceptHeight,
			),
			tlv.MakePrimitiveRecord(acceptTimeType, &acceptTime),
			tlv.MakePrimitiveRecord(resolveTimeType, &resolveTime),
			tlv.MakePrimitiveRecord(expiryHeightType, &htlc.Expiry),
			tlv.MakePrimitiveRecord(htlcStateType, &state),
		)
		if err != nil {
			return nil, err
		}

		if err := tlvStream.Decode(htlcReader); err != nil {
			return nil, err
		}

		key.ChanID = lnwire.NewShortChanIDFromInt(chanID)
		htlc.AcceptTime = time.Unix(0, int64(acceptTime))
		htlc.ResolveTime = time.Unix(0, int64(resolveTime))
		htlc.State = HtlcState(state)
		htlc.Amt = lnwire.MilliSatoshi(amt)

		htlcs[key] = &htlc
	}

	return htlcs, nil
}
