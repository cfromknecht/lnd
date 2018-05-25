package wtwire_test

/*
import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/lightninglabs/sauron/justicekit"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
)

var (
	testRevocation, _ = hex.DecodeString("84ce619249ae6d081c40257a3d19722ac9f4a9e06d623d3dcea19425acfe93aa")
	testSig, _        = hex.DecodeString("f9dc3dde58e004a509be9fc114dbce1d8ec7a25abf46393ae39398089eb57c29f95e3d42bed37c4f3698ea4a94fd09e26ff03a6ae6545f473deee5697d9fb48bc120c992825efed676")
	testKey, _        = hex.DecodeString("22e6c8a248f336f47ff7854b93af7fb83ea1e74fb554df2e0f38956c1f279f8f")
)

func TestStateUpdateEncryption(t *testing.T) {

	var revocation [32]byte
	copy(revocation[:], testRevocation[:])
	fmt.Println("rv:", hex.EncodeToString(revocation[:]))

	var sig [73]byte
	copy(sig[:], testSig[:])
	fmt.Println("sig:", hex.EncodeToString(sig[:]))

	upd := &justicekit.StateUpdate{
		Revocation: revocation,
		SweepSig:   sig[:],
	}

	fmt.Println(upd)

	var key chainhash.Hash
	copy(key[:], testKey[:])
	fmt.Println("key:", hex.EncodeToString(key[:]))

	enc, err := upd.Encrypt(&key)
	if err != nil {
		t.Fatalf("unable to encrypt: %v", err)
	}

	fmt.Println("enc:", enc)

	s, err := justicekit.DecryptStateUpdate(enc, &key)
	if err != nil {
		t.Fatalf("failed decrypting state update: %v", err)
	}

	if !bytes.Equal(s.Revocation[:], upd.Revocation[:]) {
		t.Fatalf("decrypted revocation did not match original")
	}

	if !bytes.Equal(s.SweepSig[:], upd.SweepSig[:]) {
		t.Fatalf("decrypted signature did not match original")
	}
}
*/
