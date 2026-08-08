// Package main runs the g0efilter controller manager.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	"github.com/g0lab/g0efilter/controller/internal/certs"
	"github.com/g0lab/g0efilter/controller/internal/controller"
	g0webhook "github.com/g0lab/g0efilter/controller/internal/webhook"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	webhookserver "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	// certSourceSelfSigned issues and renews the certificate in-process, so a
	// cluster needs no cert-manager. certSourceExternal leaves both the Secret and
	// the caBundle to whatever issued them.
	certSourceSelfSigned = "self-signed"
	certSourceExternal   = "external"

	webhookSecretName  = "g0efilter-webhook-cert" //nolint:gosec // an object name, not a credential
	webhookServiceName = "g0efilter-webhook"
	webhookConfigName  = "g0efilter-sidecar-injector"
	webhookPath        = "/inject-sidecar"
)

// Set by GoReleaser via ldflags (wired in init()).
var (
	version = ""
	commit  = "" //nolint:gochecknoglobals
	date    = "" //nolint:gochecknoglobals
)

//nolint:gochecknoinits
func init() {
	if version == "" {
		version = "0.0.0-dev"
	}

	if commit == "" {
		commit = "none"
	}

	if date == "" {
		date = "unknown"
	}
}

type options struct {
	metricsAddr   string
	probeAddr     string
	leaderElect   bool
	printVersion  bool
	webhook       bool
	webhookPort   int
	certDir       string
	certSource    string
	certSecret    string
	webhookSvc    string
	webhookConfig string
	sidecarImage  string
}

func parseFlags() options {
	var opts options

	flag.StringVar(&opts.metricsAddr, "metrics-bind-address", ":8080", "Address the metrics endpoint binds to.")
	flag.StringVar(&opts.probeAddr, "health-probe-bind-address", ":8081", "Address the probe endpoint binds to.")
	flag.BoolVar(&opts.leaderElect, "leader-elect", true,
		"Elect a leader so only one replica reconciles at a time.")
	flag.BoolVar(&opts.printVersion, "version", false, "Print the version and exit.")
	// Off unless deploy/webhook is applied: the base deployment has no Service,
	// no MutatingWebhookConfiguration and no writable directory for the certificate.
	flag.BoolVar(&opts.webhook, "webhook", false,
		"Serve the mutating webhook that injects the sidecar into selected pods.")
	flag.IntVar(&opts.webhookPort, "webhook-port", 9443, "Port the webhook server binds to.")
	flag.StringVar(&opts.certDir, "webhook-cert-dir", "/tmp/g0efilter-certs",
		"Directory the serving certificate is read from.")
	flag.StringVar(&opts.certSource, "webhook-cert-source", certSourceSelfSigned,
		"Where the serving certificate comes from: self-signed, or external for cert-manager.")
	flag.StringVar(&opts.certSecret, "webhook-cert-secret", webhookSecretName,
		"Secret that stores the self-signed webhook certificate.")
	flag.StringVar(&opts.webhookSvc, "webhook-service-name", webhookServiceName,
		"Service name included in the webhook serving certificate.")
	flag.StringVar(&opts.webhookConfig, "webhook-config-name", webhookConfigName,
		"MutatingWebhookConfiguration whose CA bundle is updated.")
	flag.StringVar(&opts.sidecarImage, "sidecar-image", g0webhook.DefaultImage,
		"Image the webhook injects when a policy does not name one.")
	flag.Parse()

	return opts
}

func newScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()

	err := clientgoscheme.AddToScheme(scheme)
	if err != nil {
		return nil, fmt.Errorf("add core scheme: %w", err)
	}

	err = v1alpha1.AddToScheme(scheme)
	if err != nil {
		return nil, fmt.Errorf("add g0efilter scheme: %w", err)
	}

	return scheme, nil
}

func run(opts options) error {
	//nolint:exhaustruct // zap defaults are appropriate for a controller
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))

	logger := ctrl.Log.WithName("setup")

	scheme, err := newScheme()
	if err != nil {
		return err
	}

	//nolint:exhaustruct // only the options this manager sets
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: opts.metricsAddr}, //nolint:exhaustruct // address only
		HealthProbeBindAddress: opts.probeAddr,
		LeaderElection:         opts.leaderElect,
		LeaderElectionID:       "g0efilter-controller.g0efilter.io",
		WebhookServer: webhookserver.NewServer(webhookserver.Options{ //nolint:exhaustruct // port and cert dir only
			Port:    opts.webhookPort,
			CertDir: opts.certDir,
		}),
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	err = startWebhook(mgr, opts)
	if err != nil {
		return err
	}

	reconciler := &controller.EgressPolicyReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}

	err = reconciler.SetupWithManager(mgr)
	if err != nil {
		return fmt.Errorf("set up the EgressPolicy controller: %w", err)
	}

	err = mgr.AddHealthzCheck("healthz", healthz.Ping)
	if err != nil {
		return fmt.Errorf("add health check: %w", err)
	}

	err = mgr.AddReadyzCheck("readyz", healthz.Ping)
	if err != nil {
		return fmt.Errorf("add ready check: %w", err)
	}

	if opts.webhook {
		err = mgr.AddReadyzCheck("webhook", mgr.GetWebhookServer().StartedChecker())
		if err != nil {
			return fmt.Errorf("add webhook ready check: %w", err)
		}
	}

	logger.Info("starting", "version", version, "commit", commit, "date", date)

	err = mgr.Start(ctrl.SetupSignalHandler())
	if err != nil {
		return fmt.Errorf("run manager: %w", err)
	}

	return nil
}

var errCertSource = errors.New("webhook-cert-source must be self-signed or external")

// namespace reads the controller's own namespace from its ServiceAccount token.
func namespace() (string, error) {
	data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "", fmt.Errorf("read the controller namespace: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}

func certOptions(opts options) (certs.Options, error) {
	ns, err := namespace()
	if err != nil {
		return certs.Options{}, err //nolint:exhaustruct // the error is the result
	}

	return certs.Options{
		Namespace:   ns,
		SecretName:  opts.certSecret,
		ServiceName: opts.webhookSvc,
		WebhookName: opts.webhookConfig,
		Dir:         opts.certDir,
	}, nil
}

// setupCertificates issues the certificate and schedules its renewal. It needs its
// own client: the manager's cache is not running yet.
func setupCertificates(mgr ctrl.Manager, opts options) error {
	if opts.certSource == certSourceExternal {
		// cert-manager mounts the Secret read-only and injects the caBundle.
		return nil
	}

	if opts.certSource != certSourceSelfSigned {
		return fmt.Errorf("%w: %q", errCertSource, opts.certSource)
	}

	certOpts, err := certOptions(opts)
	if err != nil {
		return err
	}

	scheme, err := newScheme()
	if err != nil {
		return err
	}

	direct, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme}) //nolint:exhaustruct // scheme only
	if err != nil {
		return fmt.Errorf("create a client for certificate setup: %w", err)
	}

	err = certs.Ensure(context.Background(), direct, certOpts)
	if err != nil {
		return fmt.Errorf("prepare webhook certificates: %w", err)
	}

	err = mgr.Add(certs.Renewer{Client: direct, Opts: certOpts})
	if err != nil {
		return fmt.Errorf("schedule certificate renewal: %w", err)
	}

	return nil
}

// startWebhook issues the certificate before the manager starts its listener, and
// publishes the CA before the API server sends the first admission request.
func startWebhook(mgr ctrl.Manager, opts options) error {
	if !opts.webhook {
		return nil
	}

	err := setupCertificates(mgr, opts)
	if err != nil {
		return err
	}

	injector := &g0webhook.Injector{
		Client:   mgr.GetClient(),
		Decoder:  admission.NewDecoder(mgr.GetScheme()),
		Defaults: g0webhook.Defaults{Image: opts.sidecarImage},
	}

	//nolint:exhaustruct // handler only
	mgr.GetWebhookServer().Register(webhookPath, &admission.Webhook{Handler: injector})

	return nil
}

func main() {
	opts := parseFlags()

	if opts.printVersion {
		_, _ = fmt.Fprintf(os.Stdout, "g0efilter-controller %s (%s) %s\n", version, commit, date)

		return
	}

	err := run(opts)
	if err != nil && !errors.Is(err, context.Canceled) {
		ctrl.Log.WithName("setup").Error(err, "fatal")
		os.Exit(1)
	}
}
