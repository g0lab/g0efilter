package harness

import "testing"

type canIExitError int

func (e canIExitError) Error() string { return "exit status" }
func (e canIExitError) ExitCode() int { return int(e) }

func TestParseCanIDecision(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		stdout  string
		stderr  string
		err     error
		allowed bool
		wantErr bool
	}{
		{name: "allowed", stdout: "yes\n", allowed: true},
		{name: "allowed with warning", stdout: "yes\n", stderr: "Warning: cluster scoped", allowed: true},
		{name: "denied exits one", stdout: "no\n", stderr: "Warning: cluster scoped", err: canIExitError(1)},
		{name: "denied may exit zero", stdout: "no\n"},
		{name: "denied with wrong exit", stdout: "no\n", err: canIExitError(2), wantErr: true},
		{name: "command failure", stderr: "Unable to connect to the server", err: errKubectlFailed, wantErr: true},
		{name: "empty output", wantErr: true},
		{name: "yes with command failure", stdout: "yes\n", err: canIExitError(1), wantErr: true},
		{name: "stderr decision is not trusted", stderr: "no\n", err: canIExitError(1), wantErr: true},
		{name: "embedded decision is not trusted", stdout: "error: server returned no", err: canIExitError(1), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			allowed, err := parseCanIDecision(tt.stdout, tt.stderr, tt.err)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseCanIDecision() error = %v, wantErr %t", err, tt.wantErr)
			}

			if allowed != tt.allowed {
				t.Errorf("parseCanIDecision() = %t, want %t", allowed, tt.allowed)
			}
		})
	}
}

func TestTransientDockerFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "registry metadata",
			out:  "failed to resolve source metadata: unexpected status from HEAD request: 403 Forbidden",
			want: true,
		},
		{
			name: "rate limit",
			out:  "failed to fetch anonymous token: 429 Too Many Requests",
			want: true,
		},
		{
			name: "network timeout",
			out:  "TLS handshake timeout",
			want: true,
		},
		{
			name: "compile failure",
			out:  "controller/main.go:12:2: undefined: missing",
			want: false,
		},
		{
			name: "containerfile failure",
			out:  "unknown instruction: COPYY",
			want: false,
		},
		{
			name: "missing base image",
			out:  "failed to resolve source metadata: not found",
			want: false,
		},
		{
			name: "registry authentication",
			out:  "failed to fetch anonymous token: 401 Unauthorized",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := transientDockerFailure([]byte(tt.out)); got != tt.want {
				t.Errorf("transientDockerFailure() = %t, want %t", got, tt.want)
			}
		})
	}
}
