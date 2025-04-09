package main

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/andrew-d/proxmox-service-discovery/internal/pveapi"
)

// mockProxmoxClient is a test implementation of the proxmoxClient interface
type mockProxmoxClient struct {
	nodes          []pveapi.Node
	qemuVMs        map[string][]pveapi.QEMU                  // node -> VMs
	lxcs           map[string][]pveapi.LXC                   // node -> LXCs
	qemuConfigs    map[string]pveapi.QEMUConfig              // "node/vmid" -> config
	qemuInterfaces map[string]pveapi.AgentInterfacesResponse // "node/vmid" -> interfaces
	lxcConfigs     map[string]pveapi.LXCConfig               // "node/vmid" -> config
	lxcInterfaces  map[string][]pveapi.LXCInterface          // "node/vmid" -> interfaces
}

func newMockProxmoxClient() *mockProxmoxClient {
	return &mockProxmoxClient{
		qemuVMs:        make(map[string][]pveapi.QEMU),
		lxcs:           make(map[string][]pveapi.LXC),
		qemuConfigs:    make(map[string]pveapi.QEMUConfig),
		qemuInterfaces: make(map[string]pveapi.AgentInterfacesResponse),
		lxcConfigs:     make(map[string]pveapi.LXCConfig),
		lxcInterfaces:  make(map[string][]pveapi.LXCInterface),
	}
}

func (c *mockProxmoxClient) GetNodes(ctx context.Context) ([]pveapi.Node, error) {
	return c.nodes, nil
}

func (c *mockProxmoxClient) GetQEMUVMs(ctx context.Context, node string) ([]pveapi.QEMU, error) {
	return c.qemuVMs[node], nil
}

func (c *mockProxmoxClient) GetLXCs(ctx context.Context, node string) ([]pveapi.LXC, error) {
	return c.lxcs[node], nil
}

func (c *mockProxmoxClient) GetQEMUConfig(ctx context.Context, node string, vmID int) (pveapi.QEMUConfig, error) {
	key := nodePlusVMID(node, vmID)
	return c.qemuConfigs[key], nil
}

func (c *mockProxmoxClient) GetQEMUInterfaces(ctx context.Context, node string, vmID int) (pveapi.AgentInterfacesResponse, error) {
	key := nodePlusVMID(node, vmID)
	return c.qemuInterfaces[key], nil
}

func (c *mockProxmoxClient) GetLXCConfig(ctx context.Context, node string, vmID int) (pveapi.LXCConfig, error) {
	key := nodePlusVMID(node, vmID)
	return c.lxcConfigs[key], nil
}

func (c *mockProxmoxClient) GetLXCInterfaces(ctx context.Context, node string, vmID int) ([]pveapi.LXCInterface, error) {
	key := nodePlusVMID(node, vmID)
	return c.lxcInterfaces[key], nil
}

func nodePlusVMID(node string, vmID int) string {
	return fmt.Sprintf("%s/%d", node, vmID)
}

// noopAuthProvider is a test implementation of proxmoxAuthProvider that does nothing
type noopAuthProvider struct{}

func (a *noopAuthProvider) Authenticate(ctx context.Context) error {
	return nil
}

func (a *noopAuthProvider) UpdateRequest(r *http.Request) {
	// Do nothing
}

func (a *noopAuthProvider) WriteCacheKey(w io.Writer) {
	fmt.Fprintf(w, "noop\n")
}

// mkNet0 is a helper function to return a map[string]string with a key of
// "net0" and a value of the provided string; useful for the NetworkInterfaces
// field of QEMUConfig.
func mkNet0(s string) map[string]string {
	return map[string]string{"net0": s}
}

// TestFetchQEMUAddrs tests the fetchQEMUAddrs function
func TestFetchQEMUAddrs(t *testing.T) {
	tests := []struct {
		name        string
		qemuConfig  pveapi.QEMUConfig
		interfaces  pveapi.AgentInterfacesResponse
		expectedIPs []netip.Addr
	}{
		{
			name: "static_ip_in_ipconfig0", // for cloud-init
			qemuConfig: pveapi.QEMUConfig{
				IPConfig0:         "ip=192.168.1.100/24,gw=192.168.1.1",
				NetworkInterfaces: mkNet0("virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"),
			},
			expectedIPs: []netip.Addr{netip.MustParseAddr("192.168.1.100")},
		},
		{
			name: "IP_from_agent_interfaces_with_MAC_match",
			qemuConfig: pveapi.QEMUConfig{
				NetworkInterfaces: mkNet0("virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"),
			},
			interfaces: pveapi.AgentInterfacesResponse{
				Result: []pveapi.AgentInterface{
					{
						Name:            "eth0",
						HardwareAddress: "AA:BB:CC:DD:EE:FF",
						IPAddresses: []pveapi.AgentInterfaceAddress{
							{
								Type:    "ipv4",
								Address: "192.168.1.101",
								Prefix:  24,
							},
							{
								Type:    "ipv6",
								Address: "2001:db8::1",
								Prefix:  64,
							},
						},
					},
					{
						Name:            "eth1",
						HardwareAddress: "FF:EE:DD:CC:BB:AA",
						IPAddresses: []pveapi.AgentInterfaceAddress{
							{
								Type:    "ipv4",
								Address: "10.0.0.1",
								Prefix:  24,
							},
						},
					},
				},
			},
			expectedIPs: []netip.Addr{
				netip.MustParseAddr("192.168.1.101"),
				netip.MustParseAddr("2001:db8::1"),
			},
		},
		{
			name: "IP_from_agent_interfaces_without_MAC_match",
			qemuConfig: pveapi.QEMUConfig{
				NetworkInterfaces: mkNet0("bridge=vmbr0"), // No MAC address
			},
			interfaces: pveapi.AgentInterfacesResponse{
				Result: []pveapi.AgentInterface{
					{
						Name:            "eth0",
						HardwareAddress: "AA:BB:CC:DD:EE:FF",
						IPAddresses: []pveapi.AgentInterfaceAddress{
							{
								Type:    "ipv4",
								Address: "192.168.1.101",
								Prefix:  24,
							},
						},
					},
					{
						Name:            "eth1",
						HardwareAddress: "FF:EE:DD:CC:BB:AA",
						IPAddresses: []pveapi.AgentInterfaceAddress{
							{
								Type:    "ipv4",
								Address: "10.0.0.1",
								Prefix:  24,
							},
						},
					},
					{
						Name: "lo",
						IPAddresses: []pveapi.AgentInterfaceAddress{
							{
								Type:    "ipv4",
								Address: "127.0.0.1",
								Prefix:  8,
							},
						},
					},
				},
			},
			expectedIPs: []netip.Addr{
				netip.MustParseAddr("192.168.1.101"),
				netip.MustParseAddr("10.0.0.1"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockProxmoxClient()
			mockClient.qemuConfigs["node1/100"] = tt.qemuConfig
			mockClient.qemuInterfaces["node1/100"] = tt.interfaces

			s := &server{
				host:    "https://proxmox.example.com:8006",
				dnsZone: "example.com.",
				auth:    &noopAuthProvider{},
				client:  mockClient,
			}

			// Call the function we're testing
			ips, err := s.fetchQEMUAddrs(context.Background(), "node1", 100)
			if err != nil {
				t.Fatalf("fetchQEMUAddrs returned error: %v", err)
			}

			// Sort both.
			slices.SortFunc(ips, netip.Addr.Compare)
			slices.SortFunc(tt.expectedIPs, netip.Addr.Compare)

			// Check the result
			if !reflect.DeepEqual(ips, tt.expectedIPs) {
				t.Errorf("got IPs %v, want %v", ips, tt.expectedIPs)
			}
		})
	}
}

// TestFetchLXCAddrs tests the fetchLXCAddrs function
func TestFetchLXCAddrs(t *testing.T) {
	tests := []struct {
		name        string
		lxcConfig   pveapi.LXCConfig
		interfaces  []pveapi.LXCInterface
		expectedIPs []netip.Addr
	}{
		{
			name: "static_IP_in_config",
			lxcConfig: pveapi.LXCConfig{
				NetworkInterfaces: mkNet0("name=eth0,bridge=vmbr0,gw=192.168.1.1,hwaddr=AA:BB:CC:DD:EE:FF,ip=192.168.1.100/24"),
			},
			interfaces: []pveapi.LXCInterface{{
				Name:            "eth0",
				HardwareAddress: "AA:BB:CC:DD:EE:FF",
				Inet:            "192.168.1.100/24", // need to be here too
			}},
			expectedIPs: []netip.Addr{netip.MustParseAddr("192.168.1.100")},
		},
		{
			name: "DHCP_in_config_IP_from_interfaces_with_MAC_match",
			lxcConfig: pveapi.LXCConfig{
				NetworkInterfaces: mkNet0("name=eth0,ip=dhcp,hwaddr=AA:BB:CC:DD:EE:FF"),
			},
			interfaces: []pveapi.LXCInterface{
				{
					Name:            "eth0",
					HardwareAddress: "AA:BB:CC:DD:EE:FF",
					Inet:            "192.168.1.101/24",
					Inet6:           "2001:db8::1/64",
				},
				{
					Name:            "eth1",
					HardwareAddress: "FF:EE:DD:CC:BB:AA",
					Inet:            "10.0.0.1/24",
				},
			},
			expectedIPs: []netip.Addr{
				netip.MustParseAddr("192.168.1.101"),
				netip.MustParseAddr("2001:db8::1"),
			},
		},
		{
			name: "IP_from_interfaces_without_MAC_match",
			lxcConfig: pveapi.LXCConfig{
				NetworkInterfaces: mkNet0("name=eth0"), // No MAC address
			},
			interfaces: []pveapi.LXCInterface{
				{
					Name:            "eth0",
					HardwareAddress: "AA:BB:CC:DD:EE:FF",
					Inet:            "192.168.1.101/24",
				},
				{
					Name:            "eth1",
					HardwareAddress: "FF:EE:DD:CC:BB:AA",
					Inet:            "10.0.0.1/24",
				},
				{
					Name: "lo",
					Inet: "127.0.0.1/8",
				},
			},
			expectedIPs: []netip.Addr{
				netip.MustParseAddr("192.168.1.101"),
				netip.MustParseAddr("10.0.0.1"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockProxmoxClient()
			mockClient.lxcConfigs["node1/100"] = tt.lxcConfig
			mockClient.lxcInterfaces["node1/100"] = tt.interfaces

			s := &server{
				host:    "https://proxmox.example.com:8006",
				dnsZone: "example.com.",
				auth:    &noopAuthProvider{},
				client:  mockClient,
			}

			// Call the function we're testing
			ips, err := s.fetchLXCAddrs(context.Background(), "node1", 100)
			if err != nil {
				t.Fatalf("fetchLXCAddrs returned error: %v", err)
			}

			// Sort both
			slices.SortFunc(ips, netip.Addr.Compare)
			slices.SortFunc(tt.expectedIPs, netip.Addr.Compare)

			// Check the result
			if !reflect.DeepEqual(ips, tt.expectedIPs) {
				t.Errorf("got IPs %v, want %v", ips, tt.expectedIPs)
			}
		})
	}
}

// TestFetchInventory tests the fetchInventory function
func TestFetchInventory(t *testing.T) {
	// Setup a mock client with test data
	mockClient := newMockProxmoxClient()

	// Add nodes
	mockClient.nodes = []pveapi.Node{
		{Node: "node1"},
		{Node: "node2"},
	}

	// Add QEMU VMs
	mockClient.qemuVMs["node1"] = []pveapi.QEMU{
		{VMID: 100, Name: "vm1", Status: "running", Tags: "web;prod"},
		{VMID: 101, Name: "vm2", Status: "stopped", Tags: "db;dev"}, // This one should be skipped as it's not running
	}
	mockClient.qemuVMs["node2"] = []pveapi.QEMU{
		{VMID: 102, Name: "vm3", Status: "running", Tags: "app;prod"},
	}

	// Add LXC containers
	mockClient.lxcs["node1"] = []pveapi.LXC{
		{VMID: 200, Name: "lxc1", Status: "running", Tags: "cache;prod"},
	}
	mockClient.lxcs["node2"] = []pveapi.LXC{
		{VMID: 201, Name: "lxc2", Status: "running", Tags: "web;stage"},
		{VMID: 202, Name: "lxc3", Status: "stopped", Tags: "app;dev"}, // This one should be skipped as it's not running
	}

	// Add QEMU configs and interfaces
	mockClient.qemuConfigs["node1/100"] = pveapi.QEMUConfig{
		IPConfig0:         "ip=192.168.1.100/24,gw=192.168.1.1",
		NetworkInterfaces: mkNet0("virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"),
	}
	mockClient.qemuConfigs["node2/102"] = pveapi.QEMUConfig{
		NetworkInterfaces: mkNet0("virtio=FF:EE:DD:CC:BB:AA,bridge=vmbr0"),
	}
	mockClient.qemuInterfaces["node2/102"] = pveapi.AgentInterfacesResponse{
		Result: []pveapi.AgentInterface{
			{
				Name:            "eth0",
				HardwareAddress: "FF:EE:DD:CC:BB:AA",
				IPAddresses: []pveapi.AgentInterfaceAddress{
					{
						Type:    "ipv4",
						Address: "192.168.1.102",
						Prefix:  24,
					},
				},
			},
		},
	}

	// Add LXC configs and interfaces
	mockClient.lxcConfigs["node1/200"] = pveapi.LXCConfig{
		NetworkInterfaces: mkNet0("name=eth0,ip=192.168.1.200/24,gw=192.168.1.1,hwaddr=AA:BB:CC:DD:EE:FF"),
	}
	mockClient.lxcInterfaces["node1/200"] = []pveapi.LXCInterface{
		{
			Name:            "eno1", // different name
			HardwareAddress: "AA:BB:CC:DD:EE:FF",
			Inet:            "192.168.1.200/24",
		},
	}
	mockClient.lxcConfigs["node2/201"] = pveapi.LXCConfig{
		NetworkInterfaces: mkNet0("name=eth0,ip=dhcp,hwaddr=BB:CC:DD:EE:FF:AA"),
	}
	mockClient.lxcInterfaces["node2/201"] = []pveapi.LXCInterface{
		{
			Name:            "eth0",
			HardwareAddress: "BB:CC:DD:EE:FF:AA",
			Inet:            "192.168.1.201/24",
		},
	}

	// Create a server with the mock client for testing
	s := &server{
		host:    "https://proxmox.example.com:8006",
		dnsZone: "example.com.",
		auth:    &noopAuthProvider{},
		client:  mockClient,
	}

	// Test the function
	inventory, err := s.fetchInventory(context.Background())
	if err != nil {
		t.Fatalf("fetchInventory returned error: %v", err)
	}

	// Check the results
	expectedResources := []pveInventoryItem{
		{
			Name:  "vm1",
			ID:    100,
			Node:  "node1",
			Type:  pveItemTypeQEMU,
			Tags:  stringBoolMap("web", "prod"),
			Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.100")},
		},
		{
			Name:  "vm3",
			ID:    102,
			Node:  "node2",
			Type:  pveItemTypeQEMU,
			Tags:  stringBoolMap("app", "prod"),
			Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.102")},
		},
		{
			Name:  "lxc1",
			ID:    200,
			Node:  "node1",
			Type:  pveItemTypeLXC,
			Tags:  stringBoolMap("cache", "prod"),
			Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.200")},
		},
		{
			Name:  "lxc2",
			ID:    201,
			Node:  "node2",
			Type:  pveItemTypeLXC,
			Tags:  stringBoolMap("web", "stage"),
			Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.201")},
		},
	}

	// Check the number of resources
	if len(inventory.Resources) != len(expectedResources) {
		t.Fatalf("got %d resources, want %d", len(inventory.Resources), len(expectedResources))
	}

	// Sort the resources by name for consistent comparison
	slices.SortFunc(inventory.Resources, func(a, b pveInventoryItem) int {
		return cmp.Compare(a.Name, b.Name)
	})
	slices.SortFunc(expectedResources, func(a, b pveInventoryItem) int {
		return cmp.Compare(a.Name, b.Name)
	})

	// Check each resource matches what we expect
	for i, res := range inventory.Resources {
		if res.Name != expectedResources[i].Name {
			t.Errorf("resource %d: got name %s, want %s", i, res.Name, expectedResources[i].Name)
		}
		if res.ID != expectedResources[i].ID {
			t.Errorf("resource %d: got ID %d, want %d", i, res.ID, expectedResources[i].ID)
		}
		if res.Node != expectedResources[i].Node {
			t.Errorf("resource %d: got node %s, want %s", i, res.Node, expectedResources[i].Node)
		}
		if res.Type != expectedResources[i].Type {
			t.Errorf("resource %d: got type %v, want %v", i, res.Type, expectedResources[i].Type)
		}
		if !reflect.DeepEqual(res.Tags, expectedResources[i].Tags) {
			t.Errorf("resource %d: got tags %v, want %v", i, res.Tags, expectedResources[i].Tags)
		}
		if !reflect.DeepEqual(res.Addrs, expectedResources[i].Addrs) {
			t.Errorf("resource %d: got addresses %v, want %v", i, res.Addrs, expectedResources[i].Addrs)
		}
	}
}
