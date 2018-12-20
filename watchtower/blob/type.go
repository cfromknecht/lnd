package blob

import "fmt"

// Flag represents a specify option that can be present in a Type.
type Flag uint16

const (
	// FlagReward signals that the justice transaction should contain an
	// additional output for itself. Signatures sent by the client should
	// include the reward script negotiated during session creation. Without
	// the flag, there is only one output sweeping clients funds back to
	// them solely.
	FlagReward Flag = 1 << iota

	// FlagCommitOutputs signals that the blob contains the information
	// required to sweep commitment outputs.
	FlagCommitOutputs
)

// Type returns a Type consisting solely of this flag enabled.
func (f Flag) Type() Type {
	return Type(f)
}

// Type is a bit vector composed of Flags that govern various aspects of
// reconstructing the justice transaction from an encrypted blob. The flags can
// be used to signal behaviors such as which inputs are being swept, which
// outputs should be added to the justice transaction, or modify serialization
// of the blob itself.
type Type uint16

// TypeDefault sweeps only commitment outputs to a sweep address controlled by
// the user, and does not give the tower a reward.
const TypeDefault = Type(FlagCommitOutputs)

// Has returns true if the Type has the passed flag enabled.
func (t Type) Has(flag Flag) bool {
	return Flag(t)&flag == flag
}

// TypeFromFlags creates a single Type from an arbitrary list of flags.
func TypeFromFlags(flags ...Flag) Type {
	var typ Type
	for _, flag := range flags {
		typ |= Type(flag)
	}

	return typ
}

// knownFlags maps the supported flags to their name.
var knownFlags = map[Flag]string{
	FlagReward:        "reward",
	FlagCommitOutputs: "commit-outputs",
}

// String returns a human readable description o
func (t Type) String() string {
	var ret = fmt.Sprintf("%b[", t)
	var addBar bool
	for flag, name := range knownFlags {
		if addBar {
			ret += "|"
		}

		if t.Has(flag) {
			ret += name
		} else {
			ret += "no-" + name
		}

		addBar = true
	}
	ret += "]"

	return ret
}

// supportedTypes is the set of all configurations known to be supported by the
// package.
var supportedTypes = map[Type]struct{}{
	FlagCommitOutputs.Type():                     {},
	FlagCommitOutputs.Type() | FlagReward.Type(): {},
}

// IsSupportedType returns true if the given type is supported by the package.
func IsSupportedType(blobType Type) bool {
	_, ok := supportedTypes[blobType]
	return ok
}

// SupportedTypes returns a list of all supported blob types.
func SupportedTypes() []Type {
	supported := make([]Type, len(supportedTypes))
	for t := range supportedTypes {
		supported = append(supported, t)
	}
	return supported
}
