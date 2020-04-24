package record

import (
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// AMPOnionType is the type used in the onion to reference the AMP
	// set_id field.
	AMPOnionType tlv.Type = 10

	// AMPPayloadSize is the encoded size of an AMP record's set_id.
	AMPPayloadSize uint64 = 32
)

// AMP is a record that encodes the set_id necessary for atomic multi-path
// payments.
type AMP struct {
	setID [AMPPayloadSize]byte
}

// NewAMP generate a new AMP record with the given a set_id.
func NewAMP(setID [AMPPayloadSize]byte) *AMP {
	return &AMP{
		setID: setID,
	}
}

// SetID returns the set id contained in the AMP record.
func (a *AMP) SetID() [AMPPayloadSize]byte {
	return a.setID
}

// AMPEncoder writes the AMP record to the provided io.Writer.
func AMPEncoder(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*AMP); ok {
		return tlv.EBytes32(w, &v.setID, buf)
	}
	return tlv.NewTypeForEncodingErr(val, "AMP")
}

// AMPDecoder reads the AMP record from the provided io.Reader.
func AMPDecoder(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if v, ok := val.(*AMP); ok && l == AMPPayloadSize {
		return tlv.DBytes32(r, &v.setID, buf, AMPPayloadSize)
	}
	return tlv.NewTypeForDecodingErr(val, "AMP", l, AMPPayloadSize)
}

// Record returns a tlv.Record that can be used to encode or decode this record.
func (a *AMP) Record() tlv.Record {
	return tlv.MakeStaticRecord(
		AMPOnionType, a, AMPPayloadSize, AMPEncoder, AMPDecoder,
	)
}

// String returns a human-readble description of the amp payload fields.
func (a *AMP) String() string {
	return fmt.Sprintf("set_id=%x", a.setID)
}
