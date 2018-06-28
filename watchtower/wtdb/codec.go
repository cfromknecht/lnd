package wtdb

import (
	"io"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/roasbeef/btcd/wire"
)

func WriteElement(w io.Writer, element interface{}) error {
	werr := channeldb.WriteElement(w, element)
	switch werr.(type) {
	case *channeldb.UnknownElementType:
	default:
		return werr
	}

	switch e := element.(type) {
	// TODO(conner): add types
	case wire.BitcoinNet:
		if err := channeldb.WriteElement(w, uint32(e)); err != nil {
			return err
		}

	case BreachHint:
		if _, err := w.Write(e[:]); err != nil {
			return err
		}

	case BreachKey:
		if _, err := w.Write(e[:]); err != nil {
			return err
		}
	}

	return nil
}

func WriteElements(w io.Writer, elements ...interface{}) error {
	for _, element := range elements {
		err := WriteElement(w, element)
		if err != nil {
			return err
		}
	}

	return nil
}

func ReadElement(r io.Reader, element interface{}) error {
	rerr := channeldb.ReadElement(r, element)
	switch rerr.(type) {
	case *channeldb.UnknownElementType:
	default:
		return rerr
	}

	switch e := element.(type) {
	// TODO(conner): add types
	case *wire.BitcoinNet:
		var network uint32
		if err := channeldb.ReadElement(r, &network); err != nil {
			return err
		}
		*e = wire.BitcoinNet(network)

	case *BreachHint:
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return err
		}

	case *BreachKey:
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return err
		}
	}

	return nil
}

func ReadElements(r io.Reader, element ...interface{}) error {
	for _, element := range elements {
		err := ReadElement(r, element)
		if err != nil {
			return err
		}
	}

	return nil
}
