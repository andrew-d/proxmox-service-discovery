package pveapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
)

// AuthProvider is an interface for things that can authenticate with
// the Proxmox API.
type AuthProvider interface {
	// Authenticate should be called at creation time and every hour to
	// obtain a valid authentication ticket for the Proxmox API.
	Authenticate(context.Context) error

	// UpdateRequest should be called before making a request to the Proxmox
	// API to ensure the request is authenticated.
	UpdateRequest(r *http.Request)

	// WriteCacheKey is called with an arbitrary [io.Writer], and should
	// write a string that uniquely identifies the authentication provider.
	//
	// This is used to determine if the authentication provider has changed
	// and the cache should be invalidated.
	//
	// No sensitive information should be written, as there is no guarantee
	// that the writer is protected with e.g. a password hash or
	// encryption.
	WriteCacheKey(w io.Writer)
}

// APITokenAuthProvider is an implementation of [AuthProvider] that uses a
// Proxmox API token for authentication.
type APITokenAuthProvider struct {
	User    string
	TokenID string
	Secret  string
}

func (a *APITokenAuthProvider) Authenticate(_ context.Context) error {
	return nil // no authentication needed
}

func (a *APITokenAuthProvider) UpdateRequest(r *http.Request) {
	token := fmt.Sprintf("%s!%s=%s", a.User, a.TokenID, a.Secret)
	r.Header.Set("Authorization", "PVEAPIToken="+token)
}

func (a *APITokenAuthProvider) WriteCacheKey(w io.Writer) {
	// NOTE: don't include the secret in the cache key, as it is sensitive
	fmt.Fprintf(w, "token\nuser:%s\ntoken-id:%s\n", a.User, a.TokenID)
}

// PasswordAuthProvider is an implementation of [proxmoxAuthProvider]
// that uses a username and password for authentication, periodically
// refreshing the authentication ticket.
type PasswordAuthProvider struct {
	proxmoxBaseURL string            // immutable; e.g. "https://proxmox.example.com:8006"
	user           string            // immutable; the user to authenticate as
	password       string            // immutable; the password to authenticate with
	tr             http.RoundTripper // the HTTP transport to use; nil for default

	mu     sync.RWMutex
	client *http.Client // the HTTP client to use; created on first use
	ticket string       // the current authentication ticket
	csrf   string       // the current CSRF token
}

func NewPasswordAuthProvider(tr http.RoundTripper, proxmoxBaseURL, user, password string) (*PasswordAuthProvider, error) {
	if _, err := url.Parse(proxmoxBaseURL); err != nil {
		return nil, fmt.Errorf("invalid Proxmox base URL: %w", err)
	}

	// TODO: verify that the URL is valid by making a HTTP request?
	return &PasswordAuthProvider{
		proxmoxBaseURL: proxmoxBaseURL,
		user:           user,
		password:       password,
		tr:             tr,
	}, nil
}

func (a *PasswordAuthProvider) getClient() (*http.Client, error) {
	a.mu.RLock()
	client := a.client
	a.mu.RUnlock()

	if client != nil {
		return client, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("creating cookie jar: %w", err)
		}
		client = &http.Client{
			Transport: a.tr, // use provided transport
			Jar:       jar,
		}
		a.client = client
	}
	return a.client, nil
}

func (a *PasswordAuthProvider) Authenticate(ctx context.Context) error {
	client, err := a.getClient()
	if err != nil {
		return err
	}

	uri := fmt.Sprintf("%s/api2/json/access/ticket", a.proxmoxBaseURL)

	body := url.Values{
		"username": {a.user},
		"password": {a.password},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", uri, strings.NewReader(body.Encode()))
	if err != nil {
		return fmt.Errorf("creating HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending authentication HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var data struct {
		Data struct {
			Ticket string `json:"ticket"`
			CSRF   string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.ticket = data.Data.Ticket
	a.csrf = data.Data.CSRF
	return nil
}

func (a *PasswordAuthProvider) UpdateRequest(r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	r.Header.Set("CSRFPreventionToken", a.csrf)
	r.Header.Set("Cookie", "PVEAuthCookie="+a.ticket)
}

func (a *PasswordAuthProvider) WriteCacheKey(w io.Writer) {
	// NOTE: don't include the password in the cache key, as it is sensitive
	fmt.Fprintf(w, "user-pass\nuser:%s\n", a.user)
}
