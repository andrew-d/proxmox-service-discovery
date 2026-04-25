# Proxmox Service Discovery

A DNS server that automatically discovers VMs and containers (LXCs) in your
Proxmox cluster and makes them available via DNS.

## Overview

Proxmox Service Discovery creates DNS records for all your Proxmox VMs and
containers, allowing you to access them by name instead of IP address. It
automatically detects when VMs are started, stopped, or have their IPs changed.

<!-- TODO: image here? -->

## Features

- **Automatic service discovery** - Finds all running VMs and containers in your Proxmox cluster
- **DNS resolution** - Access your VMs and containers by name (e.g., `vm-name.lab.local`)
- **IPv4 and IPv6 support** - Creates both A and AAAA records
- **Flexible filtering** - Filter services by type, tags, or networks
- **Web debug interface** - View DNS records and configuration in a simple web UI

## Installation

### Binary Release

Download the latest binary from the [releases page](https://github.com/andrew-d/proxmox-service-discovery/releases).

### Building from Source

```bash
git clone https://github.com/andrew-d/proxmox-service-discovery.git
cd proxmox-service-discovery
go build
```

## Usage

```bash
# Basic usage with password authentication
./proxmox-service-discovery \
  --proxmox-host=https://proxmox.example.com:8006 \
  --proxmox-user=user@pam \
  --proxmox-password=your-password \
  --dns-zone=lab.local

# Using API token (recommended)
./proxmox-service-discovery \
  --proxmox-host=https://proxmox.example.com:8006 \
  --proxmox-user=user@pam \
  --proxmox-token-id=my-token \
  --proxmox-token-secret=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --dns-zone=lab.local

# With filtering and debug interface
./proxmox-service-discovery \
  --proxmox-host=https://proxmox.example.com:8006 \
  --proxmox-user=root@pam \
  --proxmox-password=your-password \
  --dns-zone=lab.local \
  --filter-include-tags=dns \
  --filter-exclude-cidrs=10.0.0.0/8 \
  --debug-addr=:8080
```

### Required Flags

- `--proxmox-host`: URL of your Proxmox API
- `--dns-zone`: DNS zone to serve records for (e.g., `lab.local`)
- `--proxmox-user`: Proxmox user (e.g., `root@pam`)
- Authentication (one of):
  - `--proxmox-password`: Password for Proxmox user
  - `--proxmox-token-id` and `--proxmox-token-secret`: Proxmox API token

### Optional Flags

- `--addr`: Address to listen on for DNS (default: `:53`)
- `--udp`: Enable UDP listener (default: true)
- `--tcp`: Enable TCP listener (default: true)
- `--debug-addr`: Address for HTTP debug interface (e.g., `:8080`)
- `--verbose`: Enable verbose logging
- `--cache-path`: Path to cache file; if set, the program will save its state
  to this file and load it on startup if the initial fetch from Proxmox fails.
- `--template`: Template for generating DNS records (default: `{{ .Name }}.{{ .Zone }}`).
  Supports Go templates with fields from the resource: `.Name`, `.ID`, `.Node`, `.Type`, and `.Tags`.
  Example: `--template='{{ if index .Tags "id-dns" }}{{ .ID }}{{ else }}{{ .Name }}{{ end }}.{{ .Zone }}'`

### TLS and Connection Options

- `--tls-no-verify`: Disable TLS certificate verification (⚠️ not recommended! ⚠️)

### Filtering Options

- `--filter-type`: Filter by resource type (`QEMU` or `LXC`)
- `--filter-include-tags`: Only include resources with these tags
- `--filter-include-tags-re`: Only include resources with tags matching these regexes
- `--filter-exclude-tags`: Exclude resources with these tags
- `--filter-exclude-tags-re`: Exclude resources with tags matching these regexes
- `--filter-include-cidrs`: Only return IP addresses in these CIDRs; useful if you have private networks or VPNs that you wish to exclude
- `--filter-exclude-cidrs`: Exclude IP addresses in these CIDRs.

## Setting Up as a Service

### Systemd (Linux)

Create a file at `/etc/systemd/system/proxmox-service-discovery.service`:

```ini
[Unit]
Description=Proxmox Service Discovery
After=network.target

[Service]
ExecStart=/usr/local/bin/proxmox-service-discovery \
  --proxmox-host=https://proxmox.example.com:8006 \
  --proxmox-user=root@pam \
  --proxmox-token-id=discovery \
  --proxmox-token-secret=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --dns-zone=your-domain.local
Restart=on-failure
User=nobody
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable proxmox-service-discovery
sudo systemctl start proxmox-service-discovery
```

## Client/DNS Server Setup

TODO: more details here

## API Token Creation

For better security, use API tokens instead of your Proxmox password:

1. Log in to Proxmox web interface
2. Go to Datacenter → Permissions → API Tokens
3. Click "Add" and create a token for the user you wish to use
4. Make sure to grant the token appropriate read permissions on your cluster
   under Datacenter → Permissions; typically, the `PVEAuditor` role is
   sufficient

## Troubleshooting

Enable the debug interface to view active DNS records and configuration:

```bash
./proxmox-service-discovery --debug-addr=:8080 [other flags]
```

Then open `http://localhost:8080` in your browser.

## License

Apache 2.0 - see [LICENSE](LICENSE) for more information.
