package main

import (
	"cmp"
	"html/template"
	"maps"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"time"

	"github.com/miekg/dns"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/andrew-d/proxmox-service-discovery/internal/buildtags"
	"github.com/andrew-d/proxmox-service-discovery/internal/rghandlers"
)

// setupDebugHandlers sets up the HTTP debug server handlers
func (s *server) setupDebugHandlers() {
	// Root page
	s.debugMux.HandleFunc("/", s.handleDebugRoot)

	// Config page
	s.debugMux.HandleFunc("/config", s.handleDebugConfig)

	// DNS records page
	s.debugMux.HandleFunc("/dns", s.handleDebugDNS)

	// Health check endpoint
	s.debugMux.HandleFunc("/health", s.handleDebugHealth)

	// Version endpoint
	s.debugMux.HandleFunc("/version", s.handleDebugVersion)

	// Prometheus metrics
	s.debugMux.Handle("/metrics", promhttp.Handler())
}

// StartDebugServer starts the HTTP debug server if configured
func (s *server) StartDebugServer(rg *run.Group) {
	if s.debugAddr == "" || s.debugStarted {
		return
	}

	debugServer := &http.Server{
		Addr:    s.debugAddr,
		Handler: s.debugMux,
	}

	logger.Info("starting HTTP debug server", "addr", s.debugAddr)
	rg.Add(rghandlers.HTTPServer(debugServer))
	s.debugStarted = true
}

// Template for the debug pages
// Base layout
const baseTmplStr = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}} - Proxmox Service Discovery</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --color-text: #333;
            --color-heading: #2c3e50;
            --color-link: #3498db;
            --color-border: #eee;
            --color-table-border: #ddd;
            --color-light-bg: #f8f9fa;
            --color-hover-bg: #f5f5f5;
            --color-badge-bg: #eee;
            --color-badge-text: white;
            --color-info: #3498db;
            --color-success: #2ecc71;
            --color-warning: 243, 156, 18;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.5;
            margin: 20px;
            color: var(--color-text);
        }
        h1, h2 { margin-top: 1em; color: var(--color-heading); }
        nav {
            margin: 20px 0;
            padding: 10px 0;
            border-bottom: 1px solid var(--color-border);
        }
        nav a {
            margin-right: 15px;
            color: var(--color-link);
            text-decoration: none;
            font-weight: 500;
        }
        nav a:hover { text-decoration: underline; }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--color-table-border);
        }
	tr.warning {
	    background-color: rgba(var(--color-warning), 0.7);
	}
        th {
            background-color: var(--color-light-bg);
            font-weight: 600;
        }
        tr:hover { background-color: var(--color-hover-bg); }
	tr.warning:hover {
	    background-color: rgba(var(--color-warning), 0.9);
	}
        .container { max-width: 1200px; margin: 0 auto; }
        .badge {
            display: inline-block;
            padding: 3px 7px;
            font-size: 12px;
            font-weight: 600;
            border-radius: 3px;
            background-color: var(--color-badge-bg);
        }
        .badge-info { background-color: var(--color-info); color: var(--color-badge-text); }
        .badge-success { background-color: var(--color-success); color: var(--color-badge-text); }
        .badge-warning { background-color: rgb(var(--color-warning)); color: var(--color-badge-text); }
        pre {
            background-color: var(--color-light-bg);
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{.Title}}</h1>
        <nav>
            <a href="/">Home</a>
            <a href="/config">Configuration</a>
            <a href="/dns">DNS Records</a>
            <a href="/metrics">Metrics</a>
            <a href="/health">Health Check</a>
            <a href="/version">Version</a>
        </nav>
        {{template "content" .}}
    </div>
</body>
</html>
`

// Home page template
const homeTmplStr = `
{{define "content"}}
    <p>Welcome to the debug interface for Proxmox Service Discovery.</p>
    <p>Use the navigation links above to access different debug pages.</p>

    <h2>Quick Status</h2>
    <ul>
        <li>DNS Zone: {{.Server.DnsZone}}</li>
        <li>Proxmox Host: {{.Server.Host}}</li>
        <li>Records: {{.RecordCount}} DNS entries</li>
        <li>Last Updated: {{if .LastUpdated.IsZero}}Never{{else}}{{.LastUpdated.Format "2006-01-02 15:04:05"}}{{end}}</li>
        <li>Version: {{.Version}}</li>
    </ul>
{{end}}
`

// Configuration page template
const configTmplStr = `
{{define "content"}}
    <h2>Service Configuration</h2>
    <table>
        <tr><th>Setting</th><th>Value</th></tr>
        <tr><td>DNS Zone</td><td>{{.Server.DnsZone}}</td></tr>
        <tr><td>Proxmox Host</td><td>{{.Server.Host}}</td></tr>
        <tr><td>Debug Address</td><td>{{.Server.DebugAddr}}</td></tr>
	{{if .Server.TLSNoVerify}}
        <tr class="warning"><td>TLS No Verify</td><td>Enabled</td></tr>
	{{end}}
    </table>

    <h2>Filter Configuration</h2>
    <table>
        <tr><th>Filter</th><th>Value</th></tr>
        <tr><td>Filter Type</td><td>
	    {{if .FilterConfig.Type}}
	        {{.FilterConfig.Type}}
	    {{else}}
	        <em>All</em>
	    {{end}}
	</td></tr>

        <tr><td>Include Tags</td><td>
            {{if .FilterConfig.IncludeTags}}
                {{range .FilterConfig.IncludeTags}}
                    <span class="badge">{{.}}</span>
                {{end}}
            {{else}}
                <em>None</em>
            {{end}}
        </td></tr>

        <tr><td>Include Tag Regexes</td><td>
            {{if .FilterConfig.IncludeTagsRe}}
                {{range .FilterConfig.IncludeTagsRe}}
                    <span class="badge">{{.String}}</span>
                {{end}}
            {{else}}
                <em>None</em>
            {{end}}
        </td></tr>

        <tr><td>Exclude Tags</td><td>
            {{if .FilterConfig.ExcludeTags}}
                {{range .FilterConfig.ExcludeTags}}
                    <span class="badge">{{.}}</span>
                {{end}}
            {{else}}
                <em>None</em>
            {{end}}
        </td></tr>

        <tr><td>Exclude Tag Regexes</td><td>
            {{if .FilterConfig.ExcludeTagsRe}}
                {{range .FilterConfig.ExcludeTagsRe}}
                    <span class="badge">{{.String}}</span>
                {{end}}
            {{else}}
                <em>None</em>
            {{end}}
        </td></tr>

        <tr><td>Include CIDRs</td><td>
            {{if .FilterConfig.IncludeCIDRs}}
                {{range .FilterConfig.IncludeCIDRs}}
                    <span class="badge">{{.String}}</span>
                {{end}}
            {{else}}
                <em>None</em>
            {{end}}
        </td></tr>

        <tr><td>Exclude CIDRs</td><td>
            {{if .FilterConfig.ExcludeCIDRs}}
                {{range .FilterConfig.ExcludeCIDRs}}
                    <span class="badge">{{.String}}</span>
                {{end}}
            {{else}}
                <em>None</em>
            {{end}}
        </td></tr>
    </table>
{{end}}
`

// DNS records page template
const dnsTmplStr = `
{{define "content"}}
    <h2>DNS Records <span class="badge badge-info">{{.Records | len}}</span></h2>

    <table>
        <tr>
            <th>FQDN</th>
            <th>Type</th>
            <th>IP Addresses</th>
        </tr>
        {{range .Records}}
        <tr>
            <td>{{.FQDN}}</td>
            <td>{{.Type}}</td>
            <td>
                {{range .Addresses}}
                    {{.}}<br>
                {{end}}
            </td>
        </tr>
        {{end}}
    </table>

    {{with .NoAddrs}}
    <h2>FQDNs with No Addresses <span class="badge badge-warning">{{. | len}}</span></h2>
    <p>
        The following FQDNs have no associated IP addresses:
    </p>
    <table>
        <tr>
            <th>FQDN</th>
        </tr>
        {{range .}}
        <tr>
            <td>{{.}}</td>
        </tr>
        {{end}}
    </table>
    {{end}}
{{end}}
`

// Version page template
const versionTmplStr = `
{{define "content"}}
    <h2>Version Information</h2>
    <p>Current version: <span class="badge badge-info">{{.Version}}</span></p>
    <p>Development mode: <span class="badge">{{.IsDev}}</span></p>
{{end}}
`

var (
	// Create the base template
	baseTemplate = template.Must(template.New("base").Parse(baseTmplStr))

	// Add the content templates
	homeTemplate    = template.Must(template.Must(baseTemplate.Clone()).Parse(homeTmplStr))
	configTemplate  = template.Must(template.Must(baseTemplate.Clone()).Parse(configTmplStr))
	dnsTemplate     = template.Must(template.Must(baseTemplate.Clone()).Parse(dnsTmplStr))
	versionTemplate = template.Must(template.Must(baseTemplate.Clone()).Parse(versionTmplStr))
)

// Data structures for templates

// baseTemplateData represents the common data for all templates
type baseTemplateData struct {
	Title   string
	Version string
	IsDev   bool
}

// homeTemplateData represents the data for the home page template
type homeTemplateData struct {
	baseTemplateData
	Server      serverInfo
	RecordCount int
	LastUpdated time.Time
}

// configTemplateData represents the data for the configuration page template
type configTemplateData struct {
	baseTemplateData
	Server       serverInfo
	FilterConfig filterConfigInfo
}

// dnsTemplateData represents the data for the DNS records page template
type dnsTemplateData struct {
	baseTemplateData
	Records []dnsRecordInfo
	NoAddrs []string
}

// serverInfo represents server information for templates
type serverInfo struct {
	Host        string
	DnsZone     string
	DebugAddr   string
	TLSNoVerify bool
}

// filterConfigInfo represents filter configuration for templates
type filterConfigInfo struct {
	Type          string
	IncludeTags   []string
	IncludeTagsRe []*regexp.Regexp
	ExcludeTags   []string
	ExcludeTagsRe []*regexp.Regexp
	IncludeCIDRs  []netip.Prefix
	ExcludeCIDRs  []netip.Prefix
}

// dnsRecordInfo represents a DNS record for templates
type dnsRecordInfo struct {
	FQDN      string
	Type      string
	Addresses []string
}

// handleDebugRoot handles the debug server root page
func (s *server) handleDebugRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	s.mu.RLock()
	recordCount := len(s.records)
	lastUpdated := s.lastInventoryUpdate
	s.mu.RUnlock()

	data := homeTemplateData{
		baseTemplateData: baseTemplateData{
			Title:   "Debug Server",
			Version: buildtags.Version,
			IsDev:   buildtags.IsDev,
		},
		Server: serverInfo{
			Host:      s.host,
			DnsZone:   s.dnsZone,
			DebugAddr: s.debugAddr,
		},
		RecordCount: recordCount,
		LastUpdated: lastUpdated,
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if err := homeTemplate.Execute(w, data); err != nil {
		logger.Error("error executing home template", "error", err)
	}
}

// handleDebugConfig handles the configuration debug page
func (s *server) handleDebugConfig(w http.ResponseWriter, r *http.Request) {
	// Determine if we're verifying TLS by poking into the http client we
	// have to see if the flag is set.
	//
	// TODO: this is a bit abstraction-breaking and we should figure out a
	// better way to do this.
	tlsNoVerify := false
	if s.httpc != nil {
		if tr, ok := s.httpc.Transport.(*http.Transport); ok {
			tlsNoVerify = tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify
		}
	}

	data := configTemplateData{
		baseTemplateData: baseTemplateData{
			Title:   "Configuration",
			Version: buildtags.Version,
			IsDev:   buildtags.IsDev,
		},
		Server: serverInfo{
			Host:        s.host,
			DnsZone:     s.dnsZone,
			DebugAddr:   s.debugAddr,
			TLSNoVerify: tlsNoVerify,
		},
		FilterConfig: filterConfigInfo{
			Type:          s.fc.Type,
			IncludeTags:   s.fc.IncludeTags,
			IncludeTagsRe: s.fc.IncludeTagsRe,
			ExcludeTags:   s.fc.ExcludeTags,
			ExcludeTagsRe: s.fc.ExcludeTagsRe,
			IncludeCIDRs:  s.fc.IncludeCIDRs,
			ExcludeCIDRs:  s.fc.ExcludeCIDRs,
		},
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if err := configTemplate.Execute(w, data); err != nil {
		logger.Error("error executing config template", "error", err)
	}
}

// handleDebugDNS handles the DNS records debug page
func (s *server) handleDebugDNS(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create a sorted list of records
	fqdns := slices.Collect(maps.Keys(s.records))
	slices.Sort(fqdns)

	var records []dnsRecordInfo
	for _, fqdn := range fqdns {
		rec := s.records[fqdn]

		// Group answers by record type
		recordTypes := make(map[string][]string)

		for _, answer := range rec.Answers {
			header := answer.Header()
			recordType := dns.TypeToString[header.Rrtype]

			// Extract the IP address based on the record type
			var ipAddr string
			switch header.Rrtype {
			case dns.TypeA:
				ipAddr = answer.(*dns.A).A.String()
			case dns.TypeAAAA:
				ipAddr = answer.(*dns.AAAA).AAAA.String()
			default:
				// Handle other record types if needed
				ipAddr = "unknown"
			}

			recordTypes[recordType] = append(recordTypes[recordType], ipAddr)
		}

		// Create record info for each record type
		for recordType, addresses := range recordTypes {
			records = append(records, dnsRecordInfo{
				FQDN:      fqdn,
				Type:      recordType,
				Addresses: addresses,
			})
		}
	}

	// Sort records to ensure we have a deterministic order
	slices.SortFunc(records, func(a, b dnsRecordInfo) int {
		return cmp.Or(
			cmp.Compare(a.FQDN, b.FQDN),
			cmp.Compare(a.Type, b.Type),
		)
	})

	// For each record, sort the list of addresses as well
	for i := range records {
		slices.Sort(records[i].Addresses)
	}

	// Sort the list of FQDNs with no addresses
	noAddrs := slices.Clone(s.noAddrs)
	slices.Sort(noAddrs)

	data := dnsTemplateData{
		baseTemplateData: baseTemplateData{
			Title:   "DNS Records",
			Version: buildtags.Version,
			IsDev:   buildtags.IsDev,
		},
		Records: records,
		NoAddrs: noAddrs,
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if err := dnsTemplate.Execute(w, data); err != nil {
		logger.Error("error executing DNS template", "error", err)
	}
}

// handleDebugHealth handles the health check endpoint
func (s *server) handleDebugHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleDebugVersion handles the version endpoint
func (s *server) handleDebugVersion(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Accept") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"version":"` + buildtags.Version + `"}`))
		return
	}

	data := baseTemplateData{
		Title:   "Version Information",
		Version: buildtags.Version,
		IsDev:   buildtags.IsDev,
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if err := versionTemplate.Execute(w, data); err != nil {
		logger.Error("error executing version template", "error", err)
	}
}
