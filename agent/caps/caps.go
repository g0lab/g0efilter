// Package caps verifies the Linux capabilities g0efilter needs to program nftables.
//
// The capability is carried by file capabilities on the binaries rather than
// raised at runtime: capabilities are per-thread, and the Go runtime execs `nft`
// from an arbitrary thread, so a capset or ambient raise done from one goroutine
// does not reliably apply to the thread that spawns the child.
package caps

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// NetAdmin programs nftables and reads nflog verdicts.
const NetAdmin = unix.CAP_NET_ADMIN

// words is the number of 32-bit masks in a v3 capability set.
const words = 2

// ErrUnavailable means filtering cannot be enforced, so startup must abort rather
// than leave the workload running unfiltered.
var ErrUnavailable = errors.New("CAP_NET_ADMIN is not effective for this process")

// State reports which of the process capability sets hold a capability.
type State struct {
	Effective   bool
	Permitted   bool
	Inheritable bool
	Ambient     bool
	EUID        int
}

type sets struct {
	effective   [words]uint32
	permitted   [words]uint32
	inheritable [words]uint32
}

func has(mask [words]uint32, capability int) bool {
	return mask[capability/32]&(uint32(1)<<(capability%32)) != 0
}

func with(mask [words]uint32, capability int) [words]uint32 {
	mask[capability/32] |= uint32(1) << (capability % 32)

	return mask
}

type system interface {
	read() (sets, error)
	isAmbient(capability int) (bool, error)
	euid() int
}

// Verify reports the CAP_NET_ADMIN state and fails when it is not effective.
func Verify() (State, error) {
	return verify(linuxSystem{})
}

// Inspect reports the CAP_NET_ADMIN state without judging it.
func Inspect() (State, error) {
	return inspect(linuxSystem{})
}

func verify(sys system) (State, error) {
	state, err := inspect(sys)
	if err != nil {
		return State{}, err
	}

	if !state.Effective {
		return state, ErrUnavailable
	}

	return state, nil
}

func inspect(sys system) (State, error) {
	current, err := sys.read()
	if err != nil {
		return State{}, err
	}

	ambient, err := sys.isAmbient(NetAdmin)
	if err != nil {
		return State{}, err
	}

	return State{
		Effective:   has(current.effective, NetAdmin),
		Permitted:   has(current.permitted, NetAdmin),
		Inheritable: has(current.inheritable, NetAdmin),
		Ambient:     ambient,
		EUID:        sys.euid(),
	}, nil
}

type linuxSystem struct{}

func (linuxSystem) read() (sets, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}

	var data [words]unix.CapUserData

	err := unix.Capget(&hdr, &data[0])
	if err != nil {
		return sets{}, fmt.Errorf("capget: %w", err)
	}

	var out sets

	for i := range words {
		out.effective[i] = data[i].Effective
		out.permitted[i] = data[i].Permitted
		out.inheritable[i] = data[i].Inheritable
	}

	return out, nil
}

func (linuxSystem) isAmbient(capability int) (bool, error) {
	got, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(capability), 0, 0)
	if err != nil {
		return false, fmt.Errorf("prctl PR_CAP_AMBIENT_IS_SET: %w", err)
	}

	return got == 1, nil
}

func (linuxSystem) euid() int { return os.Geteuid() }
