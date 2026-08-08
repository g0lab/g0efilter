// Package kubeevents records egress denials as Kubernetes Events on the pod, so
// they surface in `kubectl describe pod` rather than only in the sidecar's logs.
//
// It is opt-in. All containers in a pod share one ServiceAccount, so the sidecar
// cannot grant itself permission: the workload's ServiceAccount needs create on
// events and its token has to be mounted. When anything is missing, recording is
// disabled and filtering continues unaffected.
package kubeevents

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// serviceAccountDir is where kubelet projects the pod's ServiceAccount. It is a
// variable so tests can point at a fixture directory.
var serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount" //nolint:gochecknoglobals

const (
	reasonBlocked   = "EgressBlocked"
	reasonPolicy    = "PolicyReloadFailed"
	sourceComponent = "g0efilter"

	defaultMaxEvents = 10
	requestTimeout   = 5 * time.Second
	dialTimeout      = 3 * time.Second
)

var errUnexpectedStatus = errors.New("unexpected status")

// Denial is a blocked connection worth reporting.
type Denial struct {
	Component   string
	Destination string
	Reason      string
	SourceIP    string
}

// Recorder posts Events for denials. A nil Recorder is a no-op.
type Recorder struct {
	client   *http.Client
	endpoint string
	token    string

	namespace string
	pod       string
	uid       string

	max int

	wg sync.WaitGroup

	mu         sync.Mutex
	seen       map[string]struct{}
	capped     bool
	failedOnce bool
}

// Config is everything a Recorder needs, so callers and tests can supply it
// without depending on the in-cluster file layout.
type Config struct {
	Client    *http.Client
	Endpoint  string
	Token     string
	Namespace string
	Pod       string
	UID       string
	Max       int
}

// New builds a Recorder from explicit configuration.
func New(cfg Config) *Recorder {
	if cfg.Max <= 0 {
		cfg.Max = defaultMaxEvents
	}

	return &Recorder{
		client:    cfg.Client,
		endpoint:  cfg.Endpoint,
		token:     cfg.Token,
		namespace: cfg.Namespace,
		pod:       cfg.Pod,
		uid:       cfg.UID,
		max:       cfg.Max,
		seen:      make(map[string]struct{}),
	}
}

// NewFromEnv builds a Recorder when KUBE_EVENTS=true and the pod carries enough
// Kubernetes context. A nil result means denials are not recorded as Events.
func NewFromEnv(lg *slog.Logger) *Recorder {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("KUBE_EVENTS")), "true") {
		return nil
	}

	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))

	if host == "" || port == "" {
		lg.Warn("kubeevents.disabled", "reason", "not running in a Kubernetes cluster")

		return nil
	}

	token, err := os.ReadFile(serviceAccountDir + "/token")
	if err != nil {
		lg.Warn("kubeevents.disabled",
			"reason", "no ServiceAccount token",
			"hint", "set automountServiceAccountToken: true on the pod")

		return nil
	}

	namespace := podNamespace()
	if namespace == "" {
		lg.Warn("kubeevents.disabled", "reason", "cannot determine the pod namespace")

		return nil
	}

	pod := podName()
	if pod == "" {
		lg.Warn("kubeevents.disabled",
			"reason", "cannot determine the pod name",
			"hint", "expose it as POD_NAME via the downward API")

		return nil
	}

	client, err := newClient()
	if err != nil {
		lg.Warn("kubeevents.disabled", "reason", "cannot trust the API server", "err", err)

		return nil
	}

	lg.Info("kubeevents.enabled", "namespace", namespace, "pod", pod)

	return New(Config{
		Client:    client,
		Endpoint:  fmt.Sprintf("https://%s/api/v1/namespaces/%s/events", net.JoinHostPort(host, port), namespace),
		Token:     strings.TrimSpace(string(token)),
		Namespace: namespace,
		Pod:       pod,
		UID:       strings.TrimSpace(os.Getenv("POD_UID")),
		Max:       maxEvents(),
	})
}

// podName falls back to HOSTNAME, which kubelet sets to the pod name.
func podName() string {
	if name := strings.TrimSpace(os.Getenv("POD_NAME")); name != "" {
		return name
	}

	return strings.TrimSpace(os.Getenv("HOSTNAME"))
}

func podNamespace() string {
	if ns := strings.TrimSpace(os.Getenv("POD_NAMESPACE")); ns != "" {
		return ns
	}

	raw, err := os.ReadFile(serviceAccountDir + "/namespace")
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(raw))
}

func maxEvents() int {
	raw := strings.TrimSpace(os.Getenv("KUBE_EVENTS_MAX"))
	if raw == "" {
		return defaultMaxEvents
	}

	var parsed int

	_, err := fmt.Sscanf(raw, "%d", &parsed)
	if err != nil || parsed < 0 {
		return defaultMaxEvents
	}

	return parsed
}

func newClient() (*http.Client, error) {
	pem, err := os.ReadFile(serviceAccountDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read cluster CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("read cluster CA: %w", errUnexpectedStatus)
	}

	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			DialContext:     (&net.Dialer{Timeout: dialTimeout}).DialContext,
		},
	}, nil
}

// RecordBlock reports a denial unless an equivalent one was already reported or
// the per-pod cap is reached. It never blocks the caller.
func (r *Recorder) RecordBlock(ctx context.Context, denial Denial) {
	r.record(ctx, denial.Component+"|"+denial.Destination+"|"+denial.Reason, reasonBlocked, message(denial))
}

// RecordPolicyError reports a policy the agent refused to load. The pod keeps
// enforcing the previous one, which is invisible without this.
func (r *Recorder) RecordPolicyError(ctx context.Context, cause error) {
	if cause == nil {
		return
	}

	r.record(ctx, "policy|"+cause.Error(), reasonPolicy,
		"kept the previous policy: the new one was rejected: "+cause.Error())
}

// Close waits for in-flight Event posts to finish.
func (r *Recorder) Close() {
	if r == nil {
		return
	}

	r.wg.Wait()
}

func (r *Recorder) record(ctx context.Context, key, reason, text string) {
	if r == nil {
		return
	}

	if !r.claim(key) {
		return
	}

	r.wg.Go(func() {
		r.post(ctx, reason, text)
	})
}

// claim deduplicates and enforces the cap, so a port scanner cannot flood the
// pod's event stream or the API server.
func (r *Recorder) claim(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.seen[key]; ok {
		return false
	}

	if len(r.seen) >= r.max {
		if !r.capped {
			r.capped = true

			slog.Info("kubeevents.capped",
				"max", r.max,
				"reason", "further denials are logged but not recorded as Events")
		}

		return false
	}

	r.seen[key] = struct{}{}

	return true
}

func (r *Recorder) post(ctx context.Context, reason, text string) {
	payload, err := json.Marshal(r.event(reason, text))
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(payload))
	if err != nil {
		return
	}

	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		r.reportFailure(err)

		return
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		r.reportFailure(fmt.Errorf("%w: %s", errUnexpectedStatus, resp.Status))
	}
}

// reportFailure logs the first failure only: a missing RBAC rule would otherwise
// produce one log line per denial.
func (r *Recorder) reportFailure(err error) {
	r.mu.Lock()
	first := !r.failedOnce
	r.failedOnce = true
	r.mu.Unlock()

	if first {
		slog.Warn("kubeevents.post_failed",
			"err", err,
			"hint", "the pod's ServiceAccount needs create on events in its namespace")
	}
}

func (r *Recorder) event(reason, text string) map[string]any {
	now := time.Now().UTC().Format(time.RFC3339)

	involved := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"name":       r.pod,
		"namespace":  r.namespace,
	}

	if r.uid != "" {
		involved["uid"] = r.uid
	}

	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Event",
		"metadata": map[string]any{
			"name":      r.pod + "." + randomSuffix(),
			"namespace": r.namespace,
		},
		"involvedObject": involved,
		"reason":         reason,
		"message":        text,
		"type":           "Warning",
		"source":         map[string]any{"component": sourceComponent},
		"firstTimestamp": now,
		"lastTimestamp":  now,
		"count":          1,
	}
}

func message(denial Denial) string {
	var b strings.Builder

	b.WriteString("blocked egress to ")
	b.WriteString(denial.Destination)

	if denial.Component != "" {
		b.WriteString(" (")
		b.WriteString(denial.Component)
		b.WriteString(")")
	}

	if denial.Reason != "" {
		b.WriteString(": ")
		b.WriteString(denial.Reason)
	}

	return b.String()
}

// randomSuffix keeps generated Event names unique, as the API server requires.
func randomSuffix() string {
	var buf [8]byte

	_, err := rand.Read(buf[:])
	if err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))[:16]
	}

	return hex.EncodeToString(buf[:])
}
