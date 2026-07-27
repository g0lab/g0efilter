package harness

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnsTest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		owner string
		test  string
		want  bool
	}{
		{name: "same test", owner: "TestShared", test: "TestShared", want: true},
		{name: "subtest", owner: "TestShared", test: "TestShared/phase", want: true},
		{name: "nested subtest", owner: "TestShared", test: "TestShared/phase/case", want: true},
		{name: "similarly named sibling", owner: "TestShared", test: "TestSharedStack", want: false},
		{name: "empty owner", owner: "", test: "TestShared", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := ownsTest(tt.owner, tt.test); got != tt.want {
				t.Errorf("ownsTest(%q, %q) = %v, want %v", tt.owner, tt.test, got, tt.want)
			}
		})
	}
}

func TestStackFingerprintIncludesPolicyDirectory(t *testing.T) {
	t.Parallel()

	left := StackConfig{Mode: FilterModeHTTPS, PolicyDir: "/tmp/policy-left"}
	right := StackConfig{Mode: FilterModeHTTPS, PolicyDir: "/tmp/policy-right"}

	if left.fingerprint() == right.fingerprint() {
		t.Error("stacks with distinct explicit policy directories were treated as interchangeable")
	}
}

func TestRemovePolicyDirOnlyRemovesOwnedDirectory(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	callerDir := filepath.Join(parent, "caller")
	ownedDir := filepath.Join(parent, "owned")

	for _, dir := range []string{callerDir, ownedDir} {
		err := os.Mkdir(dir, 0o750)
		if err != nil {
			t.Fatal(err)
		}
	}

	(&Stack{Config: StackConfig{PolicyDir: callerDir}}).removePolicyDir()

	_, err := os.Stat(callerDir)
	if err != nil {
		t.Fatalf("caller policy directory was removed: %v", err)
	}

	(&Stack{Config: StackConfig{PolicyDir: ownedDir}, ownsPolicyDir: true}).removePolicyDir()

	_, err = os.Stat(ownedDir)
	if !os.IsNotExist(err) {
		t.Fatalf("owned policy directory still exists: %v", err)
	}
}
