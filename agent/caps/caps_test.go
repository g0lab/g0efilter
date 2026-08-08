//nolint:testpackage // Need access to internal implementation details
package caps

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

var errFake = errors.New("fake failure")

type fakeSystem struct {
	current sets
	ambient bool

	readErr    error
	ambientErr error

	uid int
}

func newFake(effective, permitted, inheritable bool) *fakeSystem {
	f := &fakeSystem{uid: 65534} //nolint:exhaustruct // zero values are the defaults under test

	if effective {
		f.current.effective = with(f.current.effective, NetAdmin)
	}

	if permitted {
		f.current.permitted = with(f.current.permitted, NetAdmin)
	}

	if inheritable {
		f.current.inheritable = with(f.current.inheritable, NetAdmin)
	}

	return f
}

func (f *fakeSystem) read() (sets, error) {
	if f.readErr != nil {
		return sets{}, f.readErr
	}

	return f.current, nil
}

func (f *fakeSystem) isAmbient(int) (bool, error) {
	if f.ambientErr != nil {
		return false, f.ambientErr
	}

	return f.ambient, nil
}

func (f *fakeSystem) euid() int { return f.uid }

func TestHasAndWith(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		capability int
	}{
		{name: "first word", capability: unix.CAP_CHOWN},
		{name: "net_admin", capability: NetAdmin},
		{name: "last bit of first word", capability: 31},
		// CAP_AUDIT_READ lives in the second mask, which a single-word
		// implementation would silently mis-index.
		{name: "second word", capability: unix.CAP_AUDIT_READ},
		{name: "first bit of second word", capability: 32},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var mask [words]uint32

			if has(mask, tc.capability) {
				t.Fatalf("empty mask reported capability %d as present", tc.capability)
			}

			mask = with(mask, tc.capability)

			if !has(mask, tc.capability) {
				t.Errorf("capability %d missing after with()", tc.capability)
			}

			if tc.capability != NetAdmin && has(mask, NetAdmin) {
				t.Errorf("setting capability %d also set NET_ADMIN", tc.capability)
			}
		})
	}
}

func TestWithDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	var mask [words]uint32

	_ = with(mask, NetAdmin)

	if has(mask, NetAdmin) {
		t.Error("with() mutated its argument")
	}
}

func TestVerifyAcceptsEffectiveNetAdmin(t *testing.T) {
	t.Parallel()

	state, err := verify(newFake(true, true, false))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if !state.Effective || !state.Permitted {
		t.Errorf("incomplete state: %+v", state)
	}

	if state.EUID != 65534 {
		t.Errorf("EUID = %d, want 65534", state.EUID)
	}
}

// Permitted without effective is what a stripped file-capability xattr looks
// like, and it must not be mistaken for a working setup.
func TestVerifyFailsClosedWithoutEffectiveNetAdmin(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		sys  *fakeSystem
	}{
		{name: "nothing granted", sys: newFake(false, false, false)},
		{name: "permitted only", sys: newFake(false, true, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := verify(tc.sys)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("got %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestVerifyPropagatesSyscallErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(*fakeSystem)
	}{
		{name: "capget", setup: func(f *fakeSystem) { f.readErr = errFake }},
		{name: "ambient probe", setup: func(f *fakeSystem) { f.ambientErr = errFake }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sys := newFake(true, true, false)
			tc.setup(sys)

			_, err := verify(sys)
			if !errors.Is(err, errFake) {
				t.Fatalf("got %v, want the %s error", err, tc.name)
			}
		})
	}
}

func TestInspectReportsEverySet(t *testing.T) {
	t.Parallel()

	sys := newFake(true, true, false)
	sys.ambient = true

	state, err := inspect(sys)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}

	if !state.Effective || !state.Permitted || !state.Ambient {
		t.Errorf("set capabilities not reported: %+v", state)
	}

	if state.Inheritable {
		t.Errorf("inheritable wrongly reported: %+v", state)
	}
}

// The real syscall wrappers must agree with the kernel about the header version
// and mask layout; a mismatch surfaces as EINVAL rather than a wrong answer.
func TestLinuxSystemReadIsConsistent(t *testing.T) {
	t.Parallel()

	sys := linuxSystem{}

	current, err := sys.read()
	if err != nil {
		t.Fatalf("capget on the test process: %v", err)
	}

	ambient, err := sys.isAmbient(NetAdmin)
	if err != nil {
		t.Fatalf("ambient probe on the test process: %v", err)
	}

	if ambient && !has(current.permitted, NetAdmin) {
		t.Error("NET_ADMIN reported ambient but not permitted, which the kernel forbids")
	}

	if sys.euid() != unix.Geteuid() {
		t.Error("euid() disagrees with the process euid")
	}
}
