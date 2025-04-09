package pveapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

const logResponses = false

var logger *slog.Logger = slog.Default().With("package", "pveapi")

// Client defines the interface for making requests to the Proxmox API.
// This interface allows for mocking in tests.
type Client interface {
	// GetNodes retrieves the list of nodes from the Proxmox API
	GetNodes(ctx context.Context) ([]Node, error)

	// GetQEMUVMs retrieves the list of QEMU VMs for a given node
	GetQEMUVMs(ctx context.Context, node string) ([]QEMU, error)

	// GetLXCs retrieves the list of LXC containers for a given node
	GetLXCs(ctx context.Context, node string) ([]LXC, error)

	// GetQEMUConfig retrieves the configuration of a QEMU VM
	GetQEMUConfig(ctx context.Context, node string, vmID int) (QEMUConfig, error)

	// GetQEMUInterfaces retrieves the network interfaces of a QEMU VM
	GetQEMUInterfaces(ctx context.Context, node string, vmID int) (AgentInterfacesResponse, error)

	// GetLXCConfig retrieves the configuration of an LXC container
	GetLXCConfig(ctx context.Context, node string, vmID int) (LXCConfig, error)

	// GetLXCInterfaces retrieves the network interfaces of an LXC container
	GetLXCInterfaces(ctx context.Context, node string, vmID int) ([]LXCInterface, error)
}

// HTTPClient is the default implementation of Client that
// makes actual HTTP requests to the Proxmox API.
type HTTPClient struct {
	host string
	auth AuthProvider
}

// NewClient creates a new Proxmox client that communicates with the given host
// using the Proxmox HTTP API.
func NewClient(host string, auth AuthProvider) *HTTPClient {
	return &HTTPClient{
		host: host,
		auth: auth,
	}
}

func (c *HTTPClient) GetNodes(ctx context.Context) ([]Node, error) {
	return fetchFromProxmox[[]Node](c, ctx, c.host+"/api2/json/nodes")
}

func (c *HTTPClient) GetQEMUVMs(ctx context.Context, node string) ([]QEMU, error) {
	return fetchFromProxmox[[]QEMU](c, ctx, c.host+"/api2/json/nodes/"+node+"/qemu")
}

func (c *HTTPClient) GetLXCs(ctx context.Context, node string) ([]LXC, error) {
	return fetchFromProxmox[[]LXC](c, ctx, c.host+"/api2/json/nodes/"+node+"/lxc")
}

func (c *HTTPClient) GetQEMUInterfaces(ctx context.Context, node string, vmID int) (AgentInterfacesResponse, error) {
	uri := fmt.Sprintf("%s/api2/json/nodes/%s/qemu/%d/agent/network-get-interfaces", c.host, node, vmID)
	return fetchFromProxmox[AgentInterfacesResponse](c, ctx, uri)
}

// collectWithPrefix will iterate through every entry in mm, adding the values
// of any keys with the given prefix to the returned map so long as their value
// is also a string.
func collectWithPrefix(mm map[string]any, prefix string) map[string]string {
	var ret map[string]string
	for k, v := range mm {
		sv, ok := v.(string)
		if !ok {
			continue
		}
		if strings.HasPrefix(k, prefix) {
			if ret == nil {
				ret = make(map[string]string)
			}
			ret[k] = sv
		}
	}
	return ret
}

func (c *HTTPClient) GetQEMUConfig(ctx context.Context, node string, vmID int) (QEMUConfig, error) {
	uri := fmt.Sprintf("%s/api2/json/nodes/%s/qemu/%d/config", c.host, node, vmID)
	kvs, err := fetchFromProxmox[map[string]any](c, ctx, uri)
	if err != nil {
		return QEMUConfig{}, err
	}

	// Copy the IPConfig0 value to the struct
	var config QEMUConfig
	if ipConfig, ok := kvs["ipconfig0"].(string); ok {
		config.IPConfig0 = ipConfig
	}

	// Copy any entries that start with "net" to the NetworkInterfaces map.
	config.NetworkInterfaces = collectWithPrefix(kvs, "net")

	return config, nil
}

func (c *HTTPClient) GetLXCConfig(ctx context.Context, node string, vmID int) (LXCConfig, error) {
	uri := fmt.Sprintf("%s/api2/json/nodes/%s/lxc/%d/config", c.host, node, vmID)
	kvs, err := fetchFromProxmox[map[string]any](c, ctx, uri)
	if err != nil {
		return LXCConfig{}, err
	}

	// Copy any entries that start with "net" to the NetworkInterfaces map.
	var config LXCConfig
	config.NetworkInterfaces = collectWithPrefix(kvs, "net")
	return config, nil
}

func (c *HTTPClient) GetLXCInterfaces(ctx context.Context, node string, vmID int) ([]LXCInterface, error) {
	uri := fmt.Sprintf("%s/api2/json/nodes/%s/lxc/%d/interfaces", c.host, node, vmID)
	return fetchFromProxmox[[]LXCInterface](c, ctx, uri)
}

// fetchFromProxmox is a generic function that makes a GET request to the
// Proxmox API, decodes the response, and returns the data under the "Data" key
// as the specified type T.
func fetchFromProxmox[T any](c *HTTPClient, ctx context.Context, uri string) (T, error) {
	var zero T

	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return zero, fmt.Errorf("creating HTTP request: %w", err)
	}
	c.auth.UpdateRequest(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return zero, fmt.Errorf("sending HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	if logResponses {
		var buf bytes.Buffer
		reader = io.TeeReader(resp.Body, &buf)

		defer func() {
			logger.Debug("got response from server",
				slog.String("uri", uri),
				slog.String("status", resp.Status),
				slog.String("response", buf.String()),
			)
		}()
	}

	// All data in Proxmox is returned under the "Data" key.
	var ret struct {
		Data T `json:"data"`
	}
	if err := json.NewDecoder(reader).Decode(&ret); err != nil {
		return zero, fmt.Errorf("decoding response: %w", err)
	}

	return ret.Data, nil
}
