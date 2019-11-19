package migration12_test

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/coreos/bbolt"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/channeldb/migration12"
	"github.com/lightningnetwork/lnd/channeldb/migtest"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
)

var (
	// invoiceBucket is the name of the bucket within the database that
	// stores all data related to invoices no matter their final state.
	// Within the invoice bucket, each invoice is keyed by its invoice ID
	// which is a monotonically increasing uint32.
	invoiceBucket = []byte("invoices")

	preimage = lntypes.Preimage{
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	}

	hash = preimage.Hash()

	paymentAddr = [32]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	beforeInvoice0Htlcs = []byte{
		0x0b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72,
		0x6c, 0x64, 0x09, 0x62, 0x79, 0x65, 0x20, 0x77, 0x6f, 0x72,
		0x6c, 0x64, 0x06, 0x70, 0x61, 0x79, 0x72, 0x65, 0x71, 0x00,
		0x00, 0x00, 0x20, 0x00, 0x00, 0x4e, 0x94, 0x91, 0x4f, 0x00,
		0x00, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x77, 0xc4, 0xd3,
		0xd5, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x20, 0x0f, 0x01, 0x00,
		0x00, 0x00, 0x0e, 0x77, 0xd5, 0xc8, 0x1c, 0x00, 0x00, 0x00,
		0x00, 0xfe, 0x20, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x03, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xa4,
	}

	afterInvoice0Htlcs = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x0b,
		0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c,
		0x64, 0x01, 0x06, 0x70, 0x61, 0x79, 0x72, 0x65, 0x71, 0x02,
		0x0f, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x77, 0xc4, 0xd3, 0xd5,
		0x00, 0x00, 0x00, 0x00, 0xfe, 0x20, 0x03, 0x0f, 0x01, 0x00,
		0x00, 0x00, 0x0e, 0x77, 0xd5, 0xc8, 0x1c, 0x00, 0x00, 0x00,
		0x00, 0xfe, 0x20, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x05, 0x05, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x06, 0x06, 0x20, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x07, 0x08, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x08, 0x04, 0x00,
		0x00, 0x00, 0x20, 0x09, 0x08, 0x00, 0x00, 0x4e, 0x94, 0x91,
		0x4f, 0x00, 0x00, 0x0a, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x0c,
		0x01, 0x03, 0x0d, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0xa4,
	}

	beforeInvoice1Htlc = []byte{
		0x0b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72,
		0x6c, 0x64, 0x09, 0x62, 0x79, 0x65, 0x20, 0x77, 0x6f, 0x72,
		0x6c, 0x64, 0x06, 0x70, 0x61, 0x79, 0x72, 0x65, 0x71, 0x00,
		0x00, 0x00, 0x20, 0x00, 0x00, 0x4e, 0x94, 0x91, 0x4f, 0x00,
		0x00, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x77, 0xc4, 0xd3,
		0xd5, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x20, 0x0f, 0x01, 0x00,
		0x00, 0x00, 0x0e, 0x77, 0xd5, 0xc8, 0x1c, 0x00, 0x00, 0x00,
		0x00, 0xfe, 0x20, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x03, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xa4, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x01, 0x08, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x03, 0x08, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x05, 0x08, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x07, 0x04, 0x00, 0x00,
		0x00, 0x58, 0x09, 0x08, 0x00, 0x13, 0xbc, 0xbf, 0x72, 0x4e,
		0x1e, 0x00, 0x0b, 0x08, 0x00, 0x17, 0xaf, 0x4c, 0x22, 0xc4,
		0x24, 0x00, 0x0d, 0x04, 0x00, 0x00, 0x23, 0x1d, 0x0f, 0x01,
		0x02,
	}

	afterInvoice1Htlc = []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x0b,
		0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c,
		0x64, 0x01, 0x06, 0x70, 0x61, 0x79, 0x72, 0x65, 0x71, 0x02,
		0x0f, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x77, 0xc4, 0xd3, 0xd5,
		0x00, 0x00, 0x00, 0x00, 0xfe, 0x20, 0x03, 0x0f, 0x01, 0x00,
		0x00, 0x00, 0x0e, 0x77, 0xd5, 0xc8, 0x1c, 0x00, 0x00, 0x00,
		0x00, 0xfe, 0x20, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x05, 0x05, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x06, 0x06, 0x20, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x07, 0x08, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x08, 0x04, 0x00,
		0x00, 0x00, 0x20, 0x09, 0x08, 0x00, 0x00, 0x4e, 0x94, 0x91,
		0x4f, 0x00, 0x00, 0x0a, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x0c,
		0x01, 0x03, 0x0d, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0xa4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41,
		0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
		0x03, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
		0x05, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
		0x07, 0x04, 0x00, 0x00, 0x00, 0x58, 0x09, 0x08, 0x00, 0x13,
		0xbc, 0xbf, 0x72, 0x4e, 0x1e, 0x00, 0x0b, 0x08, 0x00, 0x17,
		0xaf, 0x4c, 0x22, 0xc4, 0x24, 0x00, 0x0d, 0x04, 0x00, 0x00,
		0x23, 0x1d, 0x0f, 0x01, 0x02,
	}
)

// genInvoice returns the expected invoice given the number of passed htlcs. The
// serializations above reflect the invoices generated here in their old
// encoding, with the addition of the receipt "bye world". The payment address
// and feature bits did not exist in the prior, but we expect them to be
// populated with empty values after decoding.
func genInvoice(numHtlcs int) migration12.Invoice {
	circuitKey := migration12.CircuitKey{
		ChanID: lnwire.NewShortChanIDFromInt(8),
		HtlcID: 9,
	}

	htlc := &migration12.InvoiceHTLC{
		Amt:          lnwire.MilliSatoshi(100),
		AcceptHeight: 88,
		AcceptTime:   time.Unix(5555555, 0).UTC(),
		ResolveTime:  time.Unix(6666666, 0).UTC(),
		Expiry:       8989,
		State:        migration12.HtlcState(2),
	}

	var htlcs map[migration12.CircuitKey]*migration12.InvoiceHTLC
	switch numHtlcs {
	case 0:
		htlcs = map[migration12.CircuitKey]*migration12.InvoiceHTLC{}
	case 1:
		htlcs = map[migration12.CircuitKey]*migration12.InvoiceHTLC{
			circuitKey: htlc,
		}
	default:
		panic("can only generate invoices with 0 or 1 htlcs")
	}

	return migration12.Invoice{
		Memo:           []byte("hello world"),
		PaymentRequest: []byte("payreq"),
		CreationDate:   time.Unix(3333333, 0).UTC(),
		SettleDate:     time.Unix(4444444, 0).UTC(),
		Terms: migration12.ContractTerm{
			PaymentPreimage: preimage,
			Value:           lnwire.MilliSatoshi(1000),
			FinalCltvDelta:  32,
			Expiry:          24 * time.Hour,
			Features: lnwire.NewFeatureVector(
				nil, lnwire.Features,
			),
			PaymentAddr: paymentAddr,
		},
		AddIndex:    5,
		SettleIndex: 6,
		AmtPaid:     lnwire.MilliSatoshi(420),
		State:       migration12.ContractState(3),
		Htlcs:       htlcs,
	}
}

type migrationTest struct {
	name            string
	beforeMigration func(*bbolt.Tx) error
	afterMigration  func(*bbolt.Tx) error
}

var migrationTests = []migrationTest{
	{
		name:            "no invoices",
		beforeMigration: func(*bbolt.Tx) error { return nil },
		afterMigration:  func(*bbolt.Tx) error { return nil },
	},
	{
		name:            "zero htlcs",
		beforeMigration: genBeforeMigration(beforeInvoice0Htlcs),
		afterMigration:  genAfterMigration(0, afterInvoice0Htlcs),
	},
	{
		name:            "one htlc",
		beforeMigration: genBeforeMigration(beforeInvoice1Htlc),
		afterMigration:  genAfterMigration(1, afterInvoice1Htlc),
	},
}

// genBeforeMigration creates a closure that inserts an invoice serialized under
// the old format under the test payment hash.
func genBeforeMigration(beforeBytes []byte) func(*bbolt.Tx) error {
	return func(tx *bbolt.Tx) error {
		invoices, err := tx.CreateBucketIfNotExists(
			invoiceBucket,
		)
		if err != nil {
			return err
		}

		return invoices.Put(hash[:], beforeBytes)
	}
}

// genAfterMigration creates a closure that verifies the tlv invoice migration
// succeeded, but comparing the resulting encoding of the invoice to the
// expected serialization. In addition, the decoded invoice is compared against
// the expected invoice for equality.
func genAfterMigration(numHtlcs int, afterBytes []byte) func(*bbolt.Tx) error {
	return func(tx *bbolt.Tx) error {
		invoices := tx.Bucket(invoiceBucket)
		if invoices == nil {
			return fmt.Errorf("invoice bucket not found")
		}

		// Fetch the new invoice bytes and check that they match our
		// expected serialization.
		invoiceBytes := invoices.Get(hash[:])
		if !bytes.Equal(invoiceBytes, afterBytes) {
			return fmt.Errorf("invoice bytes mismatch, "+
				"want: %x, got: %x",
				invoiceBytes, afterBytes)
		}

		// Decode the invoice using the new serialization, which is
		// imported from the migration package so that it can't be
		// modified.
		invoiceReader := bytes.NewReader(invoiceBytes)
		invoice, err := migration12.DeserializeInvoice(invoiceReader)
		if err != nil {
			return fmt.Errorf("unable to deserialize invoice: %v",
				err)
		}

		// Normalize times to UTC so the test is deterministic in all
		// timezones.
		invoice.CreationDate = invoice.CreationDate.UTC()
		invoice.SettleDate = invoice.SettleDate.UTC()
		for _, htlc := range invoice.Htlcs {
			htlc.AcceptTime = htlc.AcceptTime.UTC()
			htlc.ResolveTime = htlc.ResolveTime.UTC()
		}

		// Assert that the decoded invoice has the correct number of
		// htlcs.
		if len(invoice.Htlcs) != numHtlcs {
			return fmt.Errorf("htlc count mismatch, "+
				"want: %d, got: %d", numHtlcs,
				len(invoice.Htlcs))
		}

		// Finally, compare the decoded and expected invoices for
		// equality of the parsed fields.
		expInvoice := genInvoice(numHtlcs)
		if !reflect.DeepEqual(expInvoice, invoice) {
			return fmt.Errorf("invoice mismatch, "+
				"want: %v, got: %v",
				spew.Sdump(expInvoice), spew.Sdump(invoice))

		}

		return nil
	}
}

// TestTLVInvoiceMigration executes a suite of migration tests for moving
// invoices to use TLV for their bodies. In the process, feature bits and
// payment addresses are added to the invoice while the receipt field is
// dropped. We test a few different invoices with a varying number of HTLCs, as
// well as the case where there are no invoices present.
//
// NOTE: The test vectors each include a receipt that is not present on the
// final struct, but verifies that the field is properly removed.
func TestTLVInvoiceMigration(t *testing.T) {
	for _, test := range migrationTests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			migtest.ApplyMigration(
				t,
				test.beforeMigration,
				test.afterMigration,
				migration12.MigrateInvoiceTLV,
				false,
			)
		})
	}
}
