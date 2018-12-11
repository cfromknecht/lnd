package tlv

import (
	"errors"
	"io"
)

var (
	ErrZeroValue     = errors.New("cannot encode 0 value")
	ErrValueTooLarge = errors.New("decoded value too large")
)

func writeVarInt(w io.Writer, val uint16) error {
	// Cannot encode zero-value.
	if val == 0 {
		//return ErrZeroValue
	}

	// Decrement the value to encode, since we are only interested in
	// representing numbers in [1, 2^16).
	//val--

	/*
		var varIntBytes []byte
		switch {
		case val <= 0x7f:
			varIntBytes = []byte{byte(val)}

		case 0x7f < val && val <= 0x3fff:
			varIntBytes = []byte{
				0x80 | (0x7f & byte(val>>7)),
				byte(0x7f & val),
			}

		default:
			varIntBytes = []byte{
				0x80 | (0x7f & byte(val>>9)),
				0x80 | (0x7f & byte(val>>2)),
				byte(0x03 & val),
			}
		}
	*/
	var b [1]byte
	switch {
	case val <= 0x7f:
		b[0] = byte(val)
		_, err := w.Write(b[:])
		return err

	case 0x7f < val && val <= 0x3fff:
		b[0] = 0x80 | (0x7f & byte(val>>7))
		_, err := w.Write(b[:])
		if err != nil {
			return err
		}

		b[0] = byte(0x7f & val)
		_, err = w.Write(b[:])
		return err

	default:
		b[0] = 0x80 | (0x7f & byte(val>>9))
		_, err := w.Write(b[:])
		if err != nil {
			return err
		}

		b[0] = 0x80 | (0x7f & byte(val>>2))
		_, err = w.Write(b[:])
		if err != nil {
			return err
		}

		b[0] = byte(0x03 & val)
		_, err = w.Write(b[:])
		return err
	}
}

func readVarInt(r io.Reader) (uint16, error) {
	var bb [1]uint8
	var value uint16
	for i := 0; i < 3; i++ {
		// Read the next byte.
		_, err := r.Read(bb[:])
		//err := binary.Read(r, binary.BigEndian, &b)
		if err != nil {
			return 0, err
		}

		b := bb[0]

		// In the last iteration only requires addition of the lower two
		// bits. We make sure the value is less than 2 to avoid
		// overflowing the unit16 after adding one to the total.
		if i == 2 {
			if value&0xfffc == 0xfffc && b > 0x03 {
				return 0, ErrValueTooLarge
			}
			value |= uint16(b)
			break
		}

		// Otherwise this is the first or second iteration, we simply
		// add the lower seven bits of the byte to our running total.
		value |= uint16(0x7f & b)

		// If the high bit is not set, this was the last byte to be
		// processed.
		if b&0x80 == 0x00 {
			break
		}

		// Otherwise, there is another byte to process. Shift the bits
		// over to make room for the bits contained in the next byte.
		switch {

		// The second byte will contain 7 more bits.
		case i == 0:
			value <<= 7

		// The third byte will contain 2 more bits.
		case i == 1:
			value <<= 2
		}
	}

	// Increment the reconstructed value, since the varint scheme only
	// represents numbers in the range [1, 2^16).
	//value++

	return value, nil
}
