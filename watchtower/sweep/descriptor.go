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
	_, err := r.Read(p.RevocationPubKey[:])
	if err != nil {
		return err
	}

	_, err = r.Read(p.LocalDelayPubKey[:])
	if err != nil {
		return err
	}

	return binary.Read(r, byteOrder, &p.CSVDelay)
}

func (p *StaticScriptParams) EncodeP2WKHPubKey(w io.Writer) error {
	_, err := w.Write(p.P2WKHPubKey[:])
	return err
}

func (p *StaticScriptParams) DecodeP2WKHPubKey(r io.Reader) error {
	_, err := r.Read(p.P2WKHPubKey[:])
	return err
}

func (p *StaticScriptParams) EncodeHtlcPubkeys(w io.Writer) error {
	_, err := w.Write(p.RemoteHtlcPubKey[:])
	if err != nil {
		return err
	}

	_, err = w.Write(p.LocalHtlcPubKey[:])
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

func DescriptorFromBlob(blob, key []byte, version uint16) (*Descriptor, error) {
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
	err = desc.DecodePlaintextBlob(bytes.NewReader(plaintext), version)
	if err != nil {
		return nil, err
	}

	return desc, nil
}

func (d *Descriptor) Encrypt(key []byte, ver uint16) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	err = d.EncodePlaintextBlob(&b, ver)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())

	ctxt := aesgcm.Seal(nil, nonce, b.Bytes(), nil)

	return ctxt, nil
}

func (d *Descriptor) EncodePlaintextBlob(w io.Writer, ver uint16) error {
	switch BlobVersion(ver) {
	case BlobVersion0:
		return d.encodeV0(w)
	default:
		return ErrUnknownBlobVersion
	}
}

func (d *Descriptor) DecodePlaintextBlob(r io.Reader, ver uint16) error {
	switch BlobVersion(ver) {
	case BlobVersion0:
		return d.decodeV0(r)
	default:
		return ErrUnknownBlobVersion
	}
}

func (d *Descriptor) encodeV0(w io.Writer) error {
	err := binary.Write(w, byteOrder, d.HasP2WKHOutput)
	if err != nil {
		return err
	}

	err = binary.Write(w, byteOrder, d.NumOfferedHtlcs)
	if err != nil {
		return err
	}

	err = binary.Write(w, byteOrder, d.NumReceivedHtlcs)
	if err != nil {
		return err
	}

	err = d.Params.EncodeStatic(w)
	if err != nil {
		return err
	}

	if d.HasP2WKHOutput {
		err = d.Params.EncodeP2WKHPubKey(w)
		if err != nil {
			return err
		}
	}

	if d.NumOfferedHtlcs > 0 || d.NumReceivedHtlcs > 0 {
		err = d.Params.EncodeHtlcPubkeys(w)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *Descriptor) decodeV0(r io.Reader) error {
	err := binary.Read(r, byteOrder, &d.HasP2WKHOutput)
	if err != nil {
		return err
	}

	err = binary.Read(r, byteOrder, &d.NumOfferedHtlcs)
	if err != nil {
		return err
	}

	err = binary.Read(r, byteOrder, &d.NumReceivedHtlcs)
	if err != nil {
		return err
	}

	err = d.Params.DecodeStatic(r)
	if err != nil {
		return err
	}

	if d.HasP2WKHOutput {
		err = d.Params.DecodeP2WKHPubKey(r)
		if err != nil {
			return err
		}
	}

	if d.NumOfferedHtlcs > 0 || d.NumReceivedHtlcs > 0 {
		err = d.Params.DecodeHtlcPubkeys(r)
		if err != nil {
			return err
		}
	}

	return nil
}
