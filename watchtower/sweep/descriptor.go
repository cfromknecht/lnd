package sweep

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/txscript"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil"
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

func (d *Descriptor) CommitToLocalScript() ([]byte, error) {
	revocationPubKey, err := btcec.ParsePubKey(
		d.Params.RevocationPubKey[:], btcec.S256(),
	)
	if err != nil {
		return nil, err
	}

	localDelayedPubKey, err := btcec.ParsePubKey(
		d.Params.LocalDelayPubKey[:], btcec.S256(),
	)
	if err != nil {
		return nil, err
	}

	return lnwallet.CommitScriptToSelf(
		d.Params.CSVDelay, localDelayedPubKey, revocationPubKey,
	)
}

func (d *Descriptor) CommitP2WKHScript() []byte {
	p2wkh160 := btcutil.Hash160(d.Params.P2WKHPubKey[:])
	return append([]byte{0}, p2wkh160...)
}

type StaticScriptParams struct {
	RevocationPubKey PubKey
	LocalDelayPubKey PubKey
	CSVDelay         uint32

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

type Input interface {
	Amount() btcutil.Amount
	OutPoint() wire.OutPoint
	BuildWitness() wire.TxWitness
}

type ToLocalInput struct {
	Value         btcutil.Amount
	PrevOutPoint  wire.OutPoint
	OutputScript  []byte
	RevocationSig lnwire.Sig
}

func (o *ToLocalInput) OutPoint() wire.OutPoint {
	return o.PrevOutPoint
}

func (o *ToLocalInput) Amount() btcutil.Amount {
	return o.Value
}

func (o *ToLocalInput) BuildWitness() wire.TxWitness {
	witnessStack := wire.TxWitness(make([][]byte, 3))
	witnessStack[0] = append(o.RevocationSig[:], byte(txscript.SigHashAll))
	witnessStack[1] = []byte{1}
	witnessStack[2] = o.OutputScript

	return witnessStack
}

type P2WKHInput struct {
	Value        btcutil.Amount
	PrevOutPoint wire.OutPoint
	OutputScript []byte
	Sig          lnwire.Sig
}

func (o *P2WKHInput) Amount() btcutil.Amount {
	return o.Value
}

func (o *P2WKHInput) OutPoint() wire.OutPoint {
	return o.PrevOutPoint
}

func (o *P2WKHInput) BuildWitness() wire.TxWitness {
	witnessStack := wire.TxWitness(make([][]byte, 2))
	witnessStack[0] = append(o.Sig[:], byte(txscript.SigHashAll))
	witnessStack[1] = o.OutputScript

	return witnessStack
}

var _ Input = (*ToLocalInput)(nil)
var _ Input = (*P2WKHInput)(nil)

func DescriptorFromBlob(blob, key []byte, version uint16) (*Descriptor, error) {
	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	var nonce [12]byte
	plaintext := make([]byte, len(blob)-16)

	plaintext, err = cipher.Open(plaintext[:0], nonce[:], blob, nil)
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
	var b bytes.Buffer
	err := d.EncodePlaintextBlob(&b, ver)
	if err != nil {
		return nil, err
	}

	var nonce [12]byte
	plaintext := b.Bytes()
	ciphertext := make([]byte, len(plaintext)+16)

	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return cipher.Seal(ciphertext[:0], nonce[:], plaintext, nil), nil
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
		d.Params.P2WKHPubKey = new(PubKey)
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
