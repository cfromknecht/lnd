package wtwire

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/wire"
)

// writeElement is a one-stop shop to write the big endian representation of
// any element which is to be serialized for the wire protocol. The passed
// io.Writer should be backed by an appropriately sized byte slice, or be able
// to dynamically expand to accommodate additional data.
//
// TODO(roasbeef): this should eventually draw from a buffer pool for
// serialization.
// TODO(roasbeef): switch to var-ints for all?
func writeElement(w io.Writer, element interface{}) error {
	switch e := element.(type) {
	case uint8:
		var b [1]byte
		b[0] = e
		if _, err := w.Write(b[:]); err != nil {
			return err
		}

	case uint16:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], e)
		if _, err := w.Write(b[:]); err != nil {
			return err
		}

	case uint64:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], e)
		if _, err := w.Write(b[:]); err != nil {
			return err
		}

	case [16]byte:
		if _, err := w.Write(e[:]); err != nil {
			return err
		}

	case [32]byte:
		if _, err := w.Write(e[:]); err != nil {
			return err
		}

	case [33]byte:
		if _, err := w.Write(e[:]); err != nil {
			return err
		}

	case []byte:
		if err := wire.WriteVarBytes(w, 0, e); err != nil {
			return err
		}

	case BreachHint:
		if _, err := w.Write(e[:]); err != nil {
			return err
		}

	case SessionID:
		if _, err := w.Write(e[:]); err != nil {
			return err
		}

	case *btcec.PublicKey:
		if e == nil {
			return fmt.Errorf("cannot write nil pubkey")
		}

		var b [33]byte
		serializedPubkey := e.SerializeCompressed()
		copy(b[:], serializedPubkey)
		if _, err := w.Write(b[:]); err != nil {
			return err
		}

	default:
		return fmt.Errorf("Unknown type in writeElement: %T", e)
	}

	return nil
}

// writeElements is writes each element in the elements slice to the passed
// io.Writer using writeElement.
func writeElements(w io.Writer, elements ...interface{}) error {
	for _, element := range elements {
		err := writeElement(w, element)
		if err != nil {
			return err
		}
	}
	return nil
}

// readElement is a one-stop utility function to deserialize any datastructure
// encoded using the serialization format of lnwire.
func readElement(r io.Reader, element interface{}) error {
	switch e := element.(type) {
	case *uint8:
		var b [1]uint8
		if _, err := r.Read(b[:]); err != nil {
			return err
		}
		*e = b[0]

	case *uint16:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return err
		}
		*e = binary.BigEndian.Uint16(b[:])

	case *uint64:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return err
		}
		*e = binary.BigEndian.Uint64(b[:])

	case *[16]byte:
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return err
		}

	case *[32]byte:
		if _, err := io.ReadFull(r, e[:]); err != nil {

		}

	case *[33]byte:
		if _, err := io.ReadFull(r, e[:]); err != nil {

		}

	case *[]byte:
		bytes, err := wire.ReadVarBytes(r, 0, 66000, "[]byte")
		if err != nil {
			return err
		}
		*e = bytes

	case *BreachHint:
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return err
		}

	case *SessionID:
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return err
		}

	case **btcec.PublicKey:
		var b [btcec.PubKeyBytesLenCompressed]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return err
		}

		pubKey, err := btcec.ParsePubKey(b[:], btcec.S256())
		if err != nil {
			return err
		}
		*e = pubKey

	default:
		return fmt.Errorf("Unknown type in readElement: %T", e)
	}

	return nil
}

// readElements deserializes a variable number of elements into the passed
// io.Reader, with each element being deserialized according to the readElement
// function.
func readElements(r io.Reader, elements ...interface{}) error {
	for _, element := range elements {
		err := readElement(r, element)
		if err != nil {
			return err
		}
	}
	return nil
}
