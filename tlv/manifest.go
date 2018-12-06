package tlv

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	"github.com/lightningnetwork/lnd/watchtower/wtwire"
)

type FieldReader func(io.Reader) error

type FieldWriter func(io.Writer) error

type fieldEncoder [256]FieldWriter

type FieldParser struct {
	Reader FieldReader
	Writer FieldWriter
}

type Field struct {
	ref  interface{}
	size SizeFunc
}

type SizeFunc func() uint16

func Size1() uint16 {
	return 1
}

func Size2() uint16 {
	return 2
}

func Size4() uint16 {
	return 4
}

func Size8() uint16 {
	return 8
}

func Size32() uint16 {
	return 32
}

func Size33() uint16 {
	return 33
}

func SizeN(n uint16) SizeFunc {
	return func() uint16 {
		return n
	}
}

func SizeVar(e *[]byte) SizeFunc {
	return func() uint16 {
		return uint16(len(*e))
	}
}

func NewField(i interface{}) *Field {
	var sizeFunc SizeFunc
	switch e := i.(type) {
	case *uint8:
		sizeFunc = Size1
	case *uint16, *int16:
		sizeFunc = Size2
	case *uint32, *int32:
		sizeFunc = Size4
	case *uint64, *int64:
		sizeFunc = Size8
	case *[32]byte:
		sizeFunc = Size32
	case *[33]byte:
		sizeFunc = Size33
	case *[]byte:
		sizeFunc = SizeVar(e)
	default:
		panic("unknown type")
	}

	return &Field{
		ref:  i,
		size: sizeFunc,
	}
}

type FieldManifest map[uint8]*Field

func (m *FieldManifest) Encode(w io.Writer) error {
	var encoder [256]*Field
	for key, field := range *m {
		encoder[key] = field
	}

	var key [1]uint8
	for i, field := range encoder {
		if field == nil {
			continue
		}

		key[0] = uint8(i)
		_, err := w.Write(key[:])
		if err != nil {
			return err
		}

		length := field.size()
		err = writeVarInt(w, length)
		if err != nil {
			return err
		}

		err = wtwire.WriteElement(w, field.ref)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *FieldManifest) Decode(r io.Reader) error {
	var bb [1]uint8
	for min := 0; min < 256; min++ {
		//err := binary.Read(r, binary.BigEndian, &key)
		_, err := r.Read(bb[:])
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		key := bb[0]

		if int(key) < min {
			return errors.New("invalid key order")
		}

		length, err := readVarInt(r)
		if err != nil {
			return err
		}

		field, ok := (*m)[key]
		if ok {
			//fmt.Printf("reading (key=%d length=%d value)\n", key, length)
			err := wtwire.ReadElement(r, field.ref, &length)
			if err != nil {
				return err
			}
		} else {
			//fmt.Printf("ignoring (key=%d length: %d value\n", key, length)
			io.CopyN(ioutil.Discard, r, int64(length))

		}

		min = int(key)
	}

	return nil
}

type Manifest map[uint8]FieldParser

func (m *Manifest) Encode(w io.Writer) error {
	var encoder fieldEncoder
	for key, field := range *m {
		if field.Writer != nil {
			encoder[key] = field.Writer
		}
	}

	var b bytes.Buffer
	for i, fieldWriter := range encoder {
		if fieldWriter == nil {
			continue
		}

		var key [1]uint8
		key[0] = uint8(i)
		_, err := w.Write(key[:])
		if err != nil {
			return err
		}

		err = fieldWriter(&b)
		if err != nil {
			return err
		}

		length := uint16(b.Len())
		err = writeVarInt(w, length)
		if err != nil {
			return err
		}

		//fmt.Printf("writing (key=%d length=%d value)\n", key, length)
		_, err = w.Write(b.Bytes())
		if err != nil {
			return err
		}

		b.Reset()
	}

	return nil
}

func (m *Manifest) Decode(r io.Reader) error {
	var lastKey uint8
	var bb [1]uint8
	for count := 0; count < 256; count++ {
		//err := binary.Read(r, binary.BigEndian, &key)
		_, err := r.Read(bb[:])
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		key := bb[0]

		if count > 0 && key <= lastKey {
			return errors.New("invalid key order")
		}

		length, err := readVarInt(r)
		if err != nil {
			return err
		}

		field, ok := (*m)[key]
		if ok {
			//fmt.Printf("reading (key=%d length=%d value)\n", key, length)
			err := field.Reader(r)
			if err != nil {
				return err
			}
		} else {
			//fmt.Printf("ignoring (key=%d length: %d value\n", key, length)
			io.CopyN(ioutil.Discard, r, int64(length))

		}

		lastKey = key
	}

	return nil
}
