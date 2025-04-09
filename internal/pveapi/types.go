package pveapi

// Node is the API response for a single Proxmox node from the Proxmox API
// /api/json2/nodes endpoint.
type Node struct {
	Node string `json:"node"`
}

// LXC is the API response for a single Proxmox LXC container from the Proxmox
// API /api/json2/nodes/<node>/lxc endpoint.
type LXC struct {
	VMID   int    `json:"vmid"`
	Status string `json:"status"`
	Tags   string `json:"tags"`
	Name   string `json:"name"`
}

// QEMU is the API response for a single Proxmox QEMU VM from the Proxmox API
// /api/json2/nodes/<node>/qemu endpoint.
type QEMU struct {
	VMID   int    `json:"vmid"`
	Status string `json:"status"`
	Tags   string `json:"tags"`
	Name   string `json:"name"`
}

// QEMUConfig is the API response for the configuration of a Proxmox QEMU VM from
// the Proxmox API /api2/json/nodes/<node>/qemu/<vmid>/config endpoint.
type QEMUConfig struct {
	IPConfig0         string            `json:"ipconfig0"`
	NetworkInterfaces map[string]string `json:"-"` // e.g. "net0" => "virtio,bridge=vmbr0,firewall=1"
}

// AgentInterfacesResponse is the API response for the agent interface of a Proxmox QEMU VM
// from the Proxmox API /api2/json/nodes/<node>/qemu/<vmid>/agent/network-get-interfaces endpoint.
type AgentInterfacesResponse struct {
	Result []AgentInterface `json:"result"`
}

// AgentInterface is the API response for a single agent interface of a Proxmox QEMU VM
// from the Proxmox API /api2/json/nodes/<node>/qemu/<vmid>/agent/network-get-interfaces endpoint.
type AgentInterface struct {
	Name            string                  `json:"name"`
	HardwareAddress string                  `json:"hardware-address"`
	IPAddresses     []AgentInterfaceAddress `json:"ip-addresses"`
}

// AgentInterfaceAddress is the API response for a single IP address of a Proxmox QEMU VM
// from the Proxmox API /api2/json/nodes/<node>/qemu/<vmid>/agent/network-get-interfaces endpoint.
type AgentInterfaceAddress struct {
	Type    string `json:"ip-address-type"`
	Address string `json:"ip-address"`
	Prefix  int    `json:"prefix"`
}

// LXCInterface is the API response for a single interface of a Proxmox LXC container
// from the Proxmox API /api2/json/nodes/<node>/lxc/<vmid>/interfaces endpoint.
type LXCInterface struct {
	Name            string `json:"name"`
	HardwareAddress string `json:"hwaddr"`
	Inet            string `json:"inet"`
	Inet6           string `json:"inet6"`
}

// LXCConfig is the API response for the configuration of a Proxmox LXC container
// from the Proxmox API /api2/json/nodes/<node>/lxc/<vmid>/config endpoint.
type LXCConfig struct {
	NetworkInterfaces map[string]string `json:"-"` // e.g. "net0" => "virtio,bridge=vmbr0,firewall=1"
}
