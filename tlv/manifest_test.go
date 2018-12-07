package tlv_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/lightningnetwork/lnd/tlv"
	"github.com/lightningnetwork/lnd/watchtower/wtwire"
)

type thing struct {
	known uint32

	field1   uint32
	field9   uint32
	field10  uint32
	field100 uint32
	field101 []byte

	//manifest *tlv.Manifest
	fieldManifest *tlv.FieldManifest
}

func newThing() *thing {
	t := new(thing)

	/*
		t.manifest = &tlv.Manifest{
			1: tlv.FieldParser{
				Reader: func(r io.Reader) error {
					return wtwire.ReadElement(r, &t.field1)
				},
				Writer: func(w io.Writer) error {
					return wtwire.WriteElement(w, t.field1)
				},
			},
			9: tlv.FieldParser{
				Reader: func(r io.Reader) error {
					return wtwire.ReadElement(r, &t.field9)
				},
				Writer: func(w io.Writer) error {
					return wtwire.WriteElement(w, t.field9)
				},
			},
			10: tlv.FieldParser{
				Reader: func(r io.Reader) error {
					return wtwire.ReadElement(r, &t.field10)
				},
				Writer: func(w io.Writer) error {
					return wtwire.WriteElement(w, t.field10)
				},
			},
			100: tlv.FieldParser{
				Reader: func(r io.Reader) error {
					return wtwire.ReadElement(r, &t.field100)
				},
				Writer: func(w io.Writer) error {
					return wtwire.WriteElement(w, t.field100)
				},
			},
			101: tlv.FieldParser{
				Reader: func(r io.Reader) error {
					return wtwire.ReadElement(r, &t.field101)
				},
				Writer: func(w io.Writer) error {
					return wtwire.WriteElement(w, t.field101)
				},
			},
		}
	*/

	t.fieldManifest = &tlv.FieldManifest{
		1:   tlv.NewField(&t.field1),
		9:   tlv.NewField(&t.field9),
		10:  tlv.NewField(&t.field10),
		100: tlv.NewField(&t.field100),
		101: tlv.NewField(&t.field101),
	}

	return t

	/*
		func(key uint8, r io.Reader) error {
			switch key {
			case 1:
				return wtwire.ReadElement(r, &t.field1)
			case 9:
				return wtwire.ReadElement(r, &t.field9)
			case 10:
				return wtwire.ReadElement(r, &t.field10)
			case 100:
				return wtwire.ReadElement(r, &t.field100)
			case 101:
				return wtwire.ReadElement(r, &t.field101)
			default:
				return errors.New("unknown key")
			}
		}

		func(key uint8, w io.Writer) error {
			switch key {
			case 1:
				return wtwire.WriteElement(w, t.field1)
			case 9:
				return wtwire.WriteElement(w, t.field9)
			case 10:
				return wtwire.WriteElement(w, t.field10)
			case 100:
				return wtwire.WriteElement(w, t.field100)
			case 101:
				return wtwire.WriteElement(w, t.field101)
			default:
				return nil
			}
		}
	*/
}

func (t *thing) Encode(w io.Writer) error {
	err := wtwire.WriteElement(w, t.known)
	if err != nil {
		return err
	}

	return t.fieldManifest.Encode(w)
}

func (t *thing) EncodeNorm(w io.Writer) error {
	return wtwire.WriteElements(w,
		t.known,
		t.field1,
		t.field9,
		t.field10,
		t.field100,
		t.field101,
	)
}

func (t *thing) DecodeNorm(r io.Reader) error {
	return wtwire.ReadElements(r,
		&t.known,
		&t.field1,
		&t.field9,
		&t.field10,
		&t.field100,
		&t.field101,
	)
}
func (t *thing) Decode(r io.Reader) error {
	err := wtwire.ReadElement(r, &t.known, nil)
	if err != nil {
		return err
	}

	return t.fieldManifest.Decode(r)
}

func TestEncodeDecode(t *testing.T) {
	ting := newThing()
	ting.known = 42
	ting.field1 = 50
	ting.field9 = 5
	ting.field10 = 873
	ting.field100 = 1337
	ting.field101 = bytes.Repeat([]byte{0xaa}, 32)

	var b bytes.Buffer
	err := ting.Encode(&b)
	if err != nil {
		t.Fatalf("failed to encode the thing: %v", err)
	}

	ting2 := newThing()
	err = ting2.Decode(bytes.NewReader(b.Bytes()))
	if err != nil {
		t.Fatalf("failed to decode the thing: %v", err)
	}

	switch {
	case ting.known != ting2.known,
		ting.field1 != ting2.field1,
		ting.field9 != ting2.field9,
		ting.field10 != ting2.field10,
		ting.field100 != ting2.field100,
		bytes.Compare(ting.field101, ting2.field101) != 0:

		t.Fatalf("decoded tings not the same, want: %v got: %v",
			ting, ting2)
	}
}

var b bytes.Buffer

func BenchmarkEncodeTLV(t *testing.B) {
	ting := newThing()
	ting.field101 = bytes.Repeat([]byte{0xaa}, 32)

	t.ReportAllocs()
	t.ResetTimer()

	var err error
	for i := 0; i < t.N; i++ {
		err = ting.Encode(&b)
	}
	_ = err
}

func BenchmarkEncode(t *testing.B) {
	ting := newThing()
	ting.field101 = bytes.Repeat([]byte{0xaa}, 32)

	t.ReportAllocs()
	t.ResetTimer()

	var err error
	for i := 0; i < t.N; i++ {
		err = ting.EncodeNorm(&b)
	}
	_ = err
}

func BenchmarkDecodeTLV(t *testing.B) {
	ting := newThing()
	ting.field101 = bytes.Repeat([]byte{0xaa}, 32)
	ting.Encode(&b)

	t.ReportAllocs()
	t.ResetTimer()

	var err error
	for i := 0; i < t.N; i++ {
		err = ting.Decode(bytes.NewReader(b.Bytes()))
	}
	_ = err
}

func BenchmarkDecode(t *testing.B) {
	ting := newThing()
	ting.field101 = bytes.Repeat([]byte{0xaa}, 32)
	ting.Encode(&b)

	t.ReportAllocs()
	t.ResetTimer()

	var err error
	for i := 0; i < t.N; i++ {
		err = ting.DecodeNorm(bytes.NewReader(b.Bytes()))
	}
	_ = err
}
