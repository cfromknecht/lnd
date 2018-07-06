package sweep_test

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"reflect"
	"testing"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/watchtower/sweep"
)

func makePubKey(i uint64) sweep.PubKey {
	var pk sweep.PubKey
	binary.BigEndian.PutUint64(pk[:8], i)
	return pk
}

func newPubKey(i uint64) *sweep.PubKey {
	var pk = new(sweep.PubKey)
	binary.BigEndian.PutUint64(pk[:8], i)
	return pk
}

func makeNSigs(n int) []lnwire.Sig {
	sigs := make([]lnwire.Sig, n)
	for i := range sigs {
		binary.BigEndian.PutUint64(sigs[i][:], uint64(i))
	}
	return sigs
}

var descriptorTests = []struct {
	name             string
	encVersion       uint16
	decVersion       uint16
	revPubKey        sweep.PubKey
	delayPubKey      sweep.PubKey
	csvDelay         uint32
	hasP2wkhPubKey   bool
	p2wkhPubKey      *sweep.PubKey
	numOfferedHltcs  uint16
	numReceivedHtlcs uint16
	remoteHtlcPubKey *sweep.PubKey
	localHtlcPubKey  *sweep.PubKey
	sigs             []lnwire.Sig
	encErr           error
	decErr           error
}{
	{
		name:        "to-local output only",
		encVersion:  0,
		decVersion:  0,
		revPubKey:   makePubKey(0),
		delayPubKey: makePubKey(1),
		csvDelay:    144,
		sigs:        makeNSigs(1),
	},
	{
		name:        "unknown encrypt version",
		encVersion:  1,
		decVersion:  0,
		revPubKey:   makePubKey(0),
		delayPubKey: makePubKey(1),
		csvDelay:    144,
		encErr:      sweep.ErrUnknownBlobVersion,
	},
	{
		name:        "unknown decrypt version",
		encVersion:  0,
		decVersion:  1,
		revPubKey:   makePubKey(0),
		delayPubKey: makePubKey(1),
		csvDelay:    144,
		sigs:        makeNSigs(1),
		decErr:      sweep.ErrUnknownBlobVersion,
	},
	{
		name:           "to-local and p2wkh outputs",
		encVersion:     0,
		decVersion:     0,
		revPubKey:      makePubKey(0),
		delayPubKey:    makePubKey(1),
		csvDelay:       144,
		hasP2wkhPubKey: true,
		encErr:         sweep.ErrMissingP2WKHPubKey,
	},
	{
		name:           "to-local and p2wkh outputs",
		encVersion:     0,
		decVersion:     0,
		revPubKey:      makePubKey(0),
		delayPubKey:    makePubKey(1),
		csvDelay:       144,
		hasP2wkhPubKey: true,
		p2wkhPubKey:    newPubKey(2),
		sigs:           makeNSigs(2),
	},
	{
		name:            "to-local, p2wkh, and htlc outputs",
		encVersion:      0,
		decVersion:      0,
		revPubKey:       makePubKey(0),
		delayPubKey:     makePubKey(1),
		csvDelay:        144,
		hasP2wkhPubKey:  true,
		p2wkhPubKey:     newPubKey(2),
		numOfferedHltcs: 1,
		encErr:          sweep.ErrMissingHtlcPubKey,
	},
	{
		name:             "to-local, p2wkh, and htlc outputs",
		encVersion:       0,
		decVersion:       0,
		revPubKey:        makePubKey(0),
		delayPubKey:      makePubKey(1),
		csvDelay:         144,
		hasP2wkhPubKey:   true,
		p2wkhPubKey:      newPubKey(2),
		numReceivedHtlcs: 1,
		encErr:           sweep.ErrMissingHtlcPubKey,
	},
	{
		name:             "to-local, p2wkh, and htlc outputs",
		encVersion:       0,
		decVersion:       0,
		revPubKey:        makePubKey(0),
		delayPubKey:      makePubKey(1),
		csvDelay:         144,
		hasP2wkhPubKey:   true,
		p2wkhPubKey:      newPubKey(2),
		numOfferedHltcs:  1,
		remoteHtlcPubKey: newPubKey(3),
		encErr:           sweep.ErrMissingHtlcPubKey,
	},
	{
		name:             "to-local, p2wkh, and htlc outputs",
		encVersion:       0,
		decVersion:       0,
		revPubKey:        makePubKey(0),
		delayPubKey:      makePubKey(1),
		csvDelay:         144,
		hasP2wkhPubKey:   true,
		p2wkhPubKey:      newPubKey(2),
		numReceivedHtlcs: 1,
		localHtlcPubKey:  newPubKey(3),
		sigs:             makeNSigs(3),
		encErr:           sweep.ErrMissingHtlcPubKey,
	},
	{
		name:             "to-local, p2wkh, and htlc outputs",
		encVersion:       0,
		decVersion:       0,
		revPubKey:        makePubKey(0),
		delayPubKey:      makePubKey(1),
		csvDelay:         144,
		hasP2wkhPubKey:   true,
		p2wkhPubKey:      newPubKey(2),
		numReceivedHtlcs: 1,
		remoteHtlcPubKey: newPubKey(3),
		localHtlcPubKey:  newPubKey(4),
		sigs:             makeNSigs(3),
	},
	{
		name:             "to-local, p2wkh, and htlc outputs",
		encVersion:       0,
		decVersion:       0,
		revPubKey:        makePubKey(0),
		delayPubKey:      makePubKey(1),
		csvDelay:         144,
		hasP2wkhPubKey:   true,
		p2wkhPubKey:      newPubKey(2),
		numOfferedHltcs:  2,
		numReceivedHtlcs: 2,
		remoteHtlcPubKey: newPubKey(3),
		localHtlcPubKey:  newPubKey(4),
		sigs:             makeNSigs(6),
	},
	{
		name:             "to-local, and htlc outputs",
		encVersion:       0,
		decVersion:       0,
		revPubKey:        makePubKey(0),
		delayPubKey:      makePubKey(1),
		csvDelay:         144,
		numOfferedHltcs:  2,
		numReceivedHtlcs: 2,
		remoteHtlcPubKey: newPubKey(3),
		localHtlcPubKey:  newPubKey(4),
		sigs:             makeNSigs(5),
	},
}

func TestSweepDescriptorEncryptDecrypt(t *testing.T) {
	for i, test := range descriptorTests {
		desc := &sweep.Descriptor{
			RevocationPubKey: test.revPubKey,
			LocalDelayPubKey: test.delayPubKey,
			CSVDelay:         test.csvDelay,
			HasP2WKHOutput:   test.hasP2wkhPubKey,
			P2WKHPubKey:      test.p2wkhPubKey,
			NumOfferedHtlcs:  test.numOfferedHltcs,
			NumReceivedHtlcs: test.numReceivedHtlcs,
			RemoteHtlcPubKey: test.remoteHtlcPubKey,
			LocalHtlcPubKey:  test.localHtlcPubKey,
			Sigs:             test.sigs,
		}

		// Generate a random encryption key for the blob. The key is
		// sized at 32 byte, as in practice we will be using the remote
		// party's commitment txid as the key.
		key := make([]byte, 32)
		_, err := io.ReadFull(rand.Reader, key)
		if err != nil {
			t.Fatalf("test #%d %s -- unable to generate blob "+
				"encryption key: %v", i, test.name, err)
		}

		// Encrypt the sweep descriptor using the generated key and
		// target version for this test.
		blob, err := desc.Encrypt(key, test.encVersion)
		if err != test.encErr {
			t.Fatalf("test #%d %s -- unable to encrypt blob: %v",
				i, test.name, err)
		} else if test.encErr != nil {
			// If the test expected an encryption failure, we can
			// continue to the next test.
			continue
		}

		// Decrypt the encrypted blob, reconstructing the original sweep
		// descriptor from the decrypted contents. We use the target
		// decryption version specified by this test case.
		desc2, err := sweep.DescriptorFromBlob(blob, key, test.decVersion)
		if err != test.decErr {
			t.Fatalf("test #%d %s -- unable to decrypt blob: %v",
				i, test.name, err)
		} else if test.decErr != nil {
			// If the test expected an decryption failure, we can
			// continue to the next test.
			continue
		}

		// Check that the original sweep descriptor matches the
		// one reconstructed from the encrypted blob.
		if !reflect.DeepEqual(desc, desc2) {
			t.Fatalf("test #%d %s -- decrypted descriptor does not "+
				"match original, want: %v, got %v",
				i, test.name, desc, desc2)
		}
	}
}
