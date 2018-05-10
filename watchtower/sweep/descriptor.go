package sweep

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"

	"github.com/lightningnetwork/lnd/lnwire"
)

type BlobVersion uint16

const (
	BlobVersion0 BlobVersion = 0
)

var (
	byteOrder = binary.BigEndian

	ErrUnknownBlobVersion = errors.New("unknown blob version")
)

type PubKey [33]byte

type PaymentHash [20]byte

type Descriptor struct {
	HasP2WKHOutput   bool
	NumOfferedHtlcs  uint16
	NumReceivedHtlcs uint16

	Params StaticScriptParams
}

type StaticScriptParams struct {
	RevocationPubKey PubKey
	LocalDelayPubKey PubKey
	CSVDelay         uint64

	P2WKHPubKey      *PubKey
	RemoteHtlcPubKey *PubKey
	LocalHtlcPubKey  *PubKey
}

func (p *StaticScriptParams) EncodeStatic(w io.Writer) error {
	_, err := w.Write(p.RevocationPubKey[:])
	if err != nil {
		return err
	}

	_, err = w.Write(p.LocalDelayPubKey[:])
	if err != nil {
		return err
	}

	return binary.Write(w, byteOrder, p.CSVDelay)
}

func (p *StaticScriptParams) DecodeStatic(r io.Reader) error {
	_, err := r.Read(&p.RevocationPubKey[:])
	if err != nil {
		return err
	}

	_, err = r.Read(p.LocalDelayPubKey[:])
	if err != nil {
		return err
	}

	return binary.Read(w, byteOrder, &p.CSVDelay)
}

func (p *StaticScriptParams) DecodeP2WKHPubKey(r io.Reader) error {
	p.P2WKHPubKey = new(PubKey)
	_, err := r.Read(p.P2WKHPubKey[:])
	return err
}

func (p *StaticScriptParams) DecodeHtlcPubkeys(r io.Reader) error {
	p.RemoteHtlcPubKey = new(PubKey)
	p.LocalHtlcPubKey = new(PubKey)

	_, err := r.Read(p.RemoteHtlcPubKey[:])
	if err != nil {
		return err
	}

	_, err = r.Read(p.LocalHtlcPubKey[:])
	return err
}

type SweepableOutput interface {
	BuildWitness(*StaticScriptParams) ([]byte, error)
}

type ToLocalOutput struct {
	RevocationSig lnwire.Sig
}

func (o *ToLocalOutput) BuildWitness(params *StaticScriptParams) ([]byte, error) {
	// TODO(conner): build witness
	return nil, nil
}

type P2WKHOutput struct {
	P2WKHSig lnwire.Sig
}

func (o *P2WKHOutput) BuildWitness(params *StaticScriptParams) ([]byte, error) {
	// TODO(conner): build witness
	return nil, nil
}

var _ SweepableOutput = (*ToLocalOutput)(nil)
var _ SweepableOutput = (*P2WKHOutput)(nil)

func DescriptorFromBlob(blob, key []byte, version uint16) (Descriptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())

	plaintext, err := aesgcm.Open(nil, nonce, blob, nil)
	if err != nil {
		return nil, err
	}

	desc := &Descriptor{}
	err = desc.ParseBlobPlaintext(plaintext, version)
	if err != nil {
		return nil, err
	}

	return desc, nil
}

func (d *Descriptor) ParsePlaintextBlob(ptxt []byte, ver uint16) error {
	switch BlobVersion(ver) {
	case BlobVersion0:
		return d.parseBlobV0(ptxt)
	default:
		return ErrUnknownBlobVersion
	}
}

func (d *Descriptor) decodeV0(ptxt []byte) error {
	reader := bytes.NewReader(ptxt)

	err := binary.Read(reader, byteOrder, &d.HasP2WKHOutput)
	if err != nil {
		return err
	}

	err = binary.Read(reader, byteOrder, &d.NumOfferedHtlcs)
	if err != nil {
		return err
	}

	err = binary.Read(reader, byteOrder, &d.NumReceivedHtlcs)
	if err != nil {
		return err
	}

	err = d.Params.DecodeStatic(reader)
	if err != nil {
		return err
	}

	if d.HasP2WKHOutput {
		err = d.Params.DecodeP2WKHPubKey(reader)
		if err != nil {
			return err
		}
	}

	if d.NumOfferedHtlcs > 0 || d.NumReceivedHtlcs > 0 {
		err = d.Params.DecodeHtlcPubkeys(reader)
		if err != nil {
			return err
		}
	}

	return nil
}
