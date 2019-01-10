package blob_test

import (
	"testing"

	"github.com/lightningnetwork/lnd/watchtower/blob"
)

var unknownFlag = blob.Flag(16)

type typeStringTest struct {
	name   string
	typ    blob.Type
	expStr string
}

var typeStringTests = []typeStringTest{
	{
		name:   "commit no-reward",
		typ:    blob.TypeDefault,
		expStr: "[FlagCommitOutputs|No-FlagReward]",
	},
	{
		name:   "commit reward",
		typ:    (blob.FlagCommitOutputs | blob.FlagReward).Type(),
		expStr: "[FlagCommitOutputs|FlagReward]",
	},
	{
		name:   "unknown flag",
		typ:    unknownFlag.Type(),
		expStr: "0000000000010000[No-FlagCommitOutputs|No-FlagReward]",
	},
}

// TestTypeStrings asserts that the proper human-readable string is returned for
// various blob.Types
func TestTypeStrings(t *testing.T) {
	for _, test := range typeStringTests {
		t.Run(test.name, func(t *testing.T) {
			typeStr := test.typ.String()
			if typeStr != test.expStr {
				t.Fatalf("mismatched type string, want: %v, "+
					"got %v", test.expStr, typeStr)
			}
		})
	}
}

// TestUnknownFlagString asserts that the proper string is returned from
// unallocated flags.
func TestUnknownFlagString(t *testing.T) {
	if unknownFlag.String() != "FlagUnknown" {
		t.Fatalf("unknown flags should return FlagUnknown, instead "+
			"got: %v", unknownFlag.String())
	}
}

// TestSupportedTypes verifies that blob.IsSupported returns true for all
// blob.Types returned from blob.SupportedTypes. It also asserts that the
// blob.DefaultType returns true.
func TestSupportedTypes(t *testing.T) {
	// Assert that the package's default type is supported.
	if !blob.IsSupportedType(blob.TypeDefault) {
		t.Fatalf("default type %s is not supported", blob.TypeDefault)
	}

	// Assert that all claimed supported types are actually supported.
	for _, supType := range blob.SupportedTypes() {
		if blob.IsSupportedType(supType) {
			continue
		}

		t.Fatalf("supposedly supported type %s is not supported",
			supType)
	}
}
