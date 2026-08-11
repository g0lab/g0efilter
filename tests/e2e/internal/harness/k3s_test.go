package harness

import "testing"

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
