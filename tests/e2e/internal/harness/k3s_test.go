package harness

import "testing"

func TestParseCanIDecision(t *testing.T) {
	t.Parallel()

	commandErr := errKubectlFailed

	tests := []struct {
		name    string
		out     string
		err     error
		allowed bool
		wantErr bool
	}{
		{name: "allowed", out: "yes\n", allowed: true},
		{name: "denied exits nonzero", out: "no\n", err: commandErr},
		{name: "denied may exit zero", out: "no\n"},
		{name: "command failure", out: "Unable to connect to the server", err: commandErr, wantErr: true},
		{name: "empty output", wantErr: true},
		{name: "yes with command failure", out: "yes\n", err: commandErr, wantErr: true},
		{name: "embedded decision is not trusted", out: "error: server returned no", err: commandErr, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			allowed, err := parseCanIDecision(tt.out, tt.err)
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
