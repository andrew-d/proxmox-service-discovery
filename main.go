package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/spf13/pflag"
	"golang.org/x/net/http2"

	"github.com/andrew-d/proxmox-service-discovery/internal/buildtags"
	"github.com/andrew-d/proxmox-service-discovery/internal/pveapi"
	"github.com/andrew-d/proxmox-service-discovery/internal/pvelog"
	"github.com/andrew-d/proxmox-service-discovery/internal/rghandlers"
)

const (
	metricsNamespace = "proxmox_service_discovery"
)

var (
	proxmoxHost  = pflag.StringP("proxmox-host", "h", "", "Proxmox host to connect to")
	proxmoxUser  = pflag.StringP("proxmox-user", "u", "root@pam", "Proxmox user to connect as")
	dnsZone      = pflag.StringP("dns-zone", "z", "", "DNS zone to serve records for")
	verbose      = pflag.BoolP("verbose", "v", false, "verbose output")
	logResponses = pflag.Bool("log-responses", false, "log all responses from Proxmox")
	tlsNoVerify  = pflag.Bool("tls-no-verify", false, "disable TLS certificate verification")

	// DNS server configuration
	addr = pflag.StringP("addr", "a", ":53", "address to listen on for DNS")
	udp  = pflag.Bool("udp", true, "enable UDP listener")
	tcp  = pflag.Bool("tcp", true, "enable TCP listener")

	// Cache configuration
	cachePath = pflag.String("cache-path", "", "path to cache file (disabled if empty)")

	// Debug HTTP server configuration
	debugAddr = pflag.String("debug-addr", "", "address to listen on for HTTP debug server (disabled if empty)")

	// One of these must be set
	proxmoxPassword    = pflag.StringP("proxmox-password", "p", "", "Proxmox password to connect with")
	proxmoxTokenID     = pflag.String("proxmox-token-id", "", "Proxmox API token ID to connect with")
	proxmoxTokenSecret = pflag.String("proxmox-token-secret", "", "Proxmox API token to connect with")
)

var (
	parsedIncludeTagsRe []*regexp.Regexp
	parsedExcludeTagsRe []*regexp.Regexp
)

var (
	logger *slog.Logger = slog.Default()
)

func main() {
	ctx := context.Background()
	pflag.Parse()

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if *proxmoxHost == "" {
		pvelog.Fatal(logger, "--proxmox-host is required")
	}
	if *dnsZone == "" {
		pvelog.Fatal(logger, "--dns-zone is required")
	}
	if ss := *filterIncludeTags; len(ss) > 0 {
		parsedIncludeTagsRe = make([]*regexp.Regexp, len(ss))
		for i, s := range ss {
			parsedIncludeTagsRe[i] = regexp.MustCompile(s)
		}
	}
	if ss := *filterExcludeTags; len(ss) > 0 {
		parsedExcludeTagsRe = make([]*regexp.Regexp, len(ss))
		for i, s := range ss {
			parsedExcludeTagsRe[i] = regexp.MustCompile(s)
		}
	}

	// Create a HTTP client for use when talking to Proxmox.
	//
	// Disable TLS certificate verification.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if *tlsNoVerify {
		transport.TLSClientConfig = &tls.Config{}

		// Re-enable HTTP/2 because specifying a custom TLS config
		// will disable HTTP/2 by default.
		if err := http2.ConfigureTransport(transport); err != nil {
			pvelog.Fatal(logger, "error configuring HTTP/2 transport", pvelog.Error(err))
		}

		// Actually modify the transport now that we've configured it.
		transport.TLSClientConfig.InsecureSkipVerify = true
	}
	httpc := &http.Client{Transport: transport}

	var rg run.Group

	var auth pveapi.AuthProvider
	switch {
	case *proxmoxTokenID != "" && *proxmoxTokenSecret == "":
		pvelog.Fatal(logger, "--proxmox-token-secret is required when --proxmox-token-id is set")
	case *proxmoxTokenID == "" && *proxmoxTokenSecret != "":
		pvelog.Fatal(logger, "--proxmox-token-id is required when --proxmox-token-secret is set")

	case *proxmoxTokenID != "":
		auth = &pveapi.APITokenAuthProvider{
			User:    *proxmoxUser,
			TokenID: *proxmoxTokenID,
			Secret:  *proxmoxTokenSecret,
		}
	case *proxmoxPassword != "":
		var err error
		auth, err = pveapi.NewPasswordAuthProvider(transport, *proxmoxHost, *proxmoxUser, *proxmoxPassword)
		if err != nil {
			pvelog.Fatal(logger, "error creating password auth provider", pvelog.Error(err))
		}
	}
	if err := auth.Authenticate(context.Background()); err != nil {
		// Don't exit if we have a cache file; we can still serve
		// whatever is in the cache.
		//
		// TODO: make this fatal if we get a definitive "wrong
		// password"/"bad api token" error
		if *cachePath == "" {
			pvelog.Fatal(logger, "error authenticating with Proxmox", pvelog.Error(err))
		}
	}

	// Periodically call the auth provider's update function.
	rg.Add(rghandlers.Periodic(ctx, 15*time.Minute, func(ctx context.Context) error {
		// NOTE: we never error here, as we don't want to stop the run.Group.
		if err := auth.Authenticate(ctx); err != nil {
			logger.Error("error updating Proxmox auth", pvelog.Error(err))
		}
		return nil
	}))

	server, err := newServer(Options{
		Host:       *proxmoxHost,
		DNSZone:    *dnsZone,
		Auth:       auth,
		DebugAddr:  *debugAddr,
		CachePath:  *cachePath,
		HTTPClient: httpc,
	})
	if err != nil {
		pvelog.Fatal(logger, "error creating server", pvelog.Error(err))
	}

	// Create the DNS server.
	const shutdownTimeout = 5 * time.Second
	dnsHandler := server.dnsHandler()
	if *udp {
		udpServer := &dns.Server{
			Addr:    *addr,
			Net:     "udp",
			Handler: dnsHandler,
		}
		rg.Add(rghandlers.DNSServer(udpServer))
	}
	if *tcp {
		tcpServer := &dns.Server{
			Addr:    *addr,
			Net:     "tcp",
			Handler: dnsHandler,
		}
		rg.Add(rghandlers.DNSServer(tcpServer))
	}

	// Fetch DNS records at process start so we have a warm cache.
	logger.Info("performing initial DNS record fetch")
	if err := server.updateDNSRecords(ctx); err != nil {
		pvelog.Fatal(logger, "error fetching initial DNS records", pvelog.Error(err))
	}

	// Periodically update the DNS records.
	rg.Add(rghandlers.Periodic(ctx, 1*time.Minute, func(ctx context.Context) error {
		// NOTE: we never error here, as we don't want to stop the
		// run.Group on failure.
		if err := server.updateDNSRecords(ctx); err != nil {
			logger.Error("error updating DNS records", pvelog.Error(err))
		}
		return nil
	}))

	// Start the HTTP debug server if configured
	if *debugAddr != "" {
		server.StartDebugServer(&rg)
	}

	// Shutdown gracefully on SIGINT/SIGTERM
	rg.Add(run.SignalHandler(ctx, syscall.SIGINT, syscall.SIGTERM))

	logger.Info("proxmox-service-discovery starting")
	defer logger.Info("proxmox-service-discovery finished")

	if err := rg.Run(); err != nil {
		var signalErr run.SignalError
		if errors.As(err, &signalErr) {
			logger.Info("got signal", "signal", signalErr.Signal)
			return
		}

		logger.Error("error running", pvelog.Error(err))
	}
}

type server struct {
	// config
	host      string
	dnsZone   string // with trailing dot
	auth      pveapi.AuthProvider
	client    pveapi.Client
	fc        *FilterConfig
	filt      *Filter
	debugAddr string
	cachePath string

	dnsMux *dns.ServeMux // immutable
	httpc  *http.Client  // immutable, for Proxmox API

	// Debug HTTP server
	debugMux     *http.ServeMux // immutable, for HTTP debug server
	debugStarted bool           // whether debug server was started
	noAddrs      []string       // list of FQDNs that we don't have addresses for

	// cacheLoadOnce is used to ensure that we only load the cache once.
	cacheLoadOnce   sync.Once
	cachedInventory *pveInventory
	cachedErr       error

	// DNS state
	mu                  sync.RWMutex
	records             map[string]record
	lastInventoryUpdate time.Time // time of last successful inventory update
}

// Options contains the options for creating a [server].
//
// All fields are required unless otherwise noted.
type Options struct {
	// Host is the Proxmox host to connect to.
	Host string
	// DNSZone is the DNS zone to serve records for.
	DNSZone string
	// Auth is the authentication provider to use.
	Auth pveapi.AuthProvider
	// HTTPClient is the HTTP client to use for making requests to Proxmox.
	//
	// If nil, [http.DefaultClient] will be used.
	HTTPClient *http.Client
	// DebugAddr is the address to listen on for the debug HTTP server.
	//
	// This field is optional. If empty, no debug server will be started.
	DebugAddr string
	// CachePath is the path to the cache file. If provided, the server
	// will load records from the cache file on startup, allowing it to
	// start even if there is an error fetching the inventory from Proxmox.
	//
	// This field is optional. If empty, no cache will be used.
	CachePath string
}

// newServer creates a new server instance with the given configuration
func newServer(opts Options) (*server, error) {
	if !strings.HasSuffix(opts.DNSZone, ".") {
		opts.DNSZone += "."
	}

	fc, err := NewFilterConfigFromFlags()
	if err != nil {
		return nil, fmt.Errorf("creating filter config: %w", err)
	}
	filt, err := NewFilter(fc)
	if err != nil {
		return nil, fmt.Errorf("creating filter: %w", err)
	}

	httpc := opts.HTTPClient
	if httpc == nil {
		httpc = http.DefaultClient
	}

	s := &server{
		host:      opts.Host,
		dnsZone:   opts.DNSZone,
		auth:      opts.Auth,
		client:    pveapi.NewClient(httpc, opts.Host, opts.Auth),
		httpc:     httpc,
		fc:        fc,
		filt:      filt,
		dnsMux:    dns.NewServeMux(),
		debugAddr: opts.DebugAddr,
		cachePath: opts.CachePath,
	}

	// Initialize the DNS request handler
	s.dnsMux.HandleFunc(opts.DNSZone, s.handleDNSRequest)

	// Initialize debug HTTP server if address is provided
	if opts.DebugAddr != "" {
		s.debugMux = http.NewServeMux()
		s.setupDebugHandlers()
	}

	return s, nil
}

type record struct {
	FQDN    string   // the name of the record (e.g. "foo.example.com")
	Answers []dns.RR // the DNS records to return
}

func (s *server) updateDNSRecords(ctx context.Context) error {
	// Fetch the current inventory
	inventory, err := s.fetchInventory(ctx)
	if err != nil {
		return fmt.Errorf("fetching inventory: %w", err)
	}

	// Filter the inventory to only include resources we care about.
	filtered := s.filt.FilterResources(inventory.Resources)

	// Create the DNS record map.
	var (
		noAddrs []string
		records = make(map[string]record)
	)
	for _, item := range filtered {
		fqdn := item.Name + "." + s.dnsZone

		if len(item.Addrs) == 0 {
			logger.Warn("no addresses for resource", "fqdn", fqdn)
			noAddrs = append(noAddrs, fqdn)
			continue
		}

		var answers []dns.RR
		for _, addr := range item.Addrs {
			if addr.Is4() {
				rr := new(dns.A)
				rr.Hdr = dns.RR_Header{
					Name:   fqdn,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				}
				rr.A = addr.AsSlice()
				answers = append(answers, rr)
			} else if addr.Is6() {
				rr := new(dns.AAAA)
				rr.Hdr = dns.RR_Header{
					Name:   fqdn,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    60,
				}
				rr.AAAA = addr.AsSlice()
				answers = append(answers, rr)
			}
		}

		records[fqdn] = record{
			FQDN:    fqdn,
			Answers: answers,
		}
	}

	// Update the DNS records
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = records
	s.noAddrs = noAddrs
	return nil
}

func (s *server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if buildtags.IsDev {
		logger.Debug("DNS request", "question", r.Question)
	}

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	s.mu.RLock()
	defer s.mu.RUnlock()

	var found bool
	for _, q := range r.Question {
		rec, ok := s.records[q.Name]
		if !ok {
			continue
		}

		// Add appropriate answers based on the question type
		for _, answer := range rec.Answers {
			header := answer.Header()
			if header.Rrtype == q.Qtype {
				msg.Answer = append(msg.Answer, answer)
				found = true
			}
		}
	}

	// If we didn't find any answers, return a "not found" response.
	if !found {
		msg.SetRcode(r, dns.RcodeNameError)
	}

	if err := w.WriteMsg(msg); err != nil {
		logger.Error("error writing DNS response", pvelog.Error(err))
	}
}

func (s *server) dnsHandler() dns.Handler {
	var ret dns.Handler = s.dnsMux

	// Apply middleware
	ret = dnsMetricMiddleware{ret}

	// Initialize our DNS metrics to zero.
	for _, proto := range []string{"tcp", "udp"} {
		for _, q := range []string{"A", "AAAA"} {
			dnsQueryCount.WithLabelValues(proto, q).Add(0)
		}
	}

	return ret
}

type dnsMetricMiddleware struct {
	inner dns.Handler
}

var (
	dnsQueryCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "dns_query_count",
			Help:      "Number of DNS queries received",
		},
		[]string{"protocol", "query_type"},
	)

	// Immediately curry these metrics so we can use them in the
	// middleware, without paying a per-query performance penalty.
	dnsTCPQueryCountA    = dnsQueryCount.WithLabelValues("tcp", "A")
	dnsTCPQueryCountAAAA = dnsQueryCount.WithLabelValues("tcp", "AAAA")
	dnsUDPQueryCountA    = dnsQueryCount.WithLabelValues("udp", "A")
	dnsUDPQueryCountAAAA = dnsQueryCount.WithLabelValues("udp", "AAAA")
)

func (d dnsMetricMiddleware) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	isUDP := true
	if w.RemoteAddr().Network() == "tcp" {
		isUDP = false
	}

	for _, q := range r.Question {
		// Fast path
		switch {
		case q.Qtype == dns.TypeA && isUDP:
			dnsUDPQueryCountA.Inc()
		case q.Qtype == dns.TypeAAAA && isUDP:
			dnsUDPQueryCountAAAA.Inc()
		case q.Qtype == dns.TypeA && !isUDP:
			dnsTCPQueryCountA.Inc()
		case q.Qtype == dns.TypeAAAA && !isUDP:
			dnsTCPQueryCountAAAA.Inc()
		default:
			// Slow path: allocate and increment the correct metric.
			ty := dns.TypeToString[q.Qtype]
			if ty == "" {
				ty = fmt.Sprintf("unknown_%d", q.Qtype)
			}

			var proto string
			if isUDP {
				proto = "udp"
			} else {
				proto = "tcp"
			}
			dnsQueryCount.WithLabelValues(proto, ty).Inc()
		}
	}
	d.inner.ServeDNS(w, r)
}
