package wtwire

/*
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/lnwire"
)

const EncryptedBlobSize = 512

var byteOrder = binary.BigEndian

type SweepDetails struct {
	Revocation [32]byte
	SweepSig   lnwire.Sig
}

func (s *SweepDetails) Serialize() ([]byte, error) {
	var b bytes.Buffer
	_, err := b.Write(s.Revocation[:])
	if err != nil {
		return nil, err
	}

	_, err = b.Write(s.SweepSig[:])
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func (s *SweepDetails) Deserialize(b []byte) error {
	r := bytes.NewReader(b)

	if _, err := io.ReadFull(r, s.Revocation[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, s.SweepSig[:]); err != nil {
		return err
	}

	return nil

}

func EncryptSweepDetails(s *SweepDetails, key BreachKey) ([]byte, error) {

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	fmt.Println(block)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := s.Serialize()
	if err != nil {
		return nil, err
	}

	// TODO: Is this really safe/correct?
	// To make sure we always end up with the same ciphertext for
	// an uniques state, we use the firs bytes of the key as nonce.
	// This is safe because this key will _only_ be used to encrypt
	// this particular state.
	nonce := make([]byte, aesgcm.NonceSize())
	copy(nonce[:], key[:])

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

func DecryptSweepDetails(ciphertext []byte, key BreachKey) (*SweepDetails, error) {

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// TODO: Is this really safe/correct?
	// To make sure we always end up with the same ciphertext for
	// an uniques state, we use the firs bytes of the key as nonce.
	// This is safe because this key will _only_ be used to encrypt
	// this particular state.
	nonce := make([]byte, aesgcm.NonceSize())
	copy(nonce[:], key[:])

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	s := &SweepDetails{}
	if err := s.Deserialize(plaintext); err != nil {
		return nil, err
	}

	return s, nil
}
*/
