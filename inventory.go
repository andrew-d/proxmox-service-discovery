package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/creachadair/taskgroup"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/andrew-d/proxmox-service-discovery/internal/pveapi"
	"github.com/andrew-d/proxmox-service-discovery/internal/pvelog"
)

const (
	// currentCacheVersion is the version of the cache file format.
	currentCacheVersion = 1

	// inventorySubsystem is the Prometheus subsystem for inventory metrics.
	inventorySubsystem = "inventory"
)

var (
	// State of the cluster
	nodeCountMetric = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: inventorySubsystem,
		Name:      "node_count",
		Help:      "Number of nodes in the Proxmox cluster",
	})
	lxcCountMetric = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: inventorySubsystem,
		Name:      "lxc_count",
		Help:      "Number of LXCs in the Proxmox cluster",
	})
	vmCountMetric = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: inventorySubsystem,
		Name:      "vm_count",
		Help:      "Number of VMs in the Proxmox cluster",
	})

	// State about inventory fetches
	lastInventoryUpdateMetric = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: inventorySubsystem,
		Name:      "last_inventory_update",
		Help:      "Unix timestamp of the last inventory update",
	})
	inventoryFetches = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: inventorySubsystem,
		Name:      "fetches_total",
		Help:      "Total number of inventory fetches",
	})
	inventoryFetchErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: inventorySubsystem,
		Name:      "fetch_errors_total",
		Help:      "Total number of inventory fetch errors",
	})
)

// pveInventory is a summary of the state of the Proxmox cluster.
type pveInventory struct {
	// Version is the version of the inventory, used to determine if a
	// cached inventory is compatible with the current version of the code.
	Version int
	// CacheKey is an (opaque) key used to identify the host/cluster that
	// this inventory belongs to. This is used to ensure that the cache
	// file is not accidentally shared between different clusters.
	CacheKey string
	// NodeNames is the list of (host) node names in the cluster.
	NodeNames []string
	// NodeStats is a summary of the inventory about each node.
	NodeStats map[string]nodeInventoryStats
	// Resources is the list of resources in the cluster.
	Resources []pveInventoryItem
}

// nodeInventoryStats is a summary of the inventory about a single node.
type nodeInventoryStats struct {
	NumVMs  int
	NumLXCs int
}

type pveInventoryItem struct {
	// Name is the name of the resource.
	Name string
	// ID is the (numeric) ID of the resource.
	ID int
	// Node is the name of the node the resource is on.
	Node string
	// Type is the type of the resource.
	Type pveItemType
	// Tags are the tags associated with the resource.
	Tags map[string]bool
	// Addrs are the IP addresses associated with the resource.
	Addrs []netip.Addr
}

type pveItemType int

const (
	pveItemTypeUnknown pveItemType = iota
	pveItemTypeLXC
	pveItemTypeQEMU
)

func (t pveItemType) String() string {
	switch t {
	case pveItemTypeLXC:
		return "LXC"
	case pveItemTypeQEMU:
		return "QEMU"
	default:
		return "unknown"
	}
}

func (s *server) inventoryCacheKey() string {
	h := sha256.New()

	// Prefix with something unique to this program so we're less likely to
	// be confused with some other cache file.
	h.Write([]byte("pve-inventory-cache\n"))

	// Hash the hostname of the cluster; this does mean that if we talk to
	// only a single host in the cluster, we won't be able to use the cache
	// on other hosts, but that seems like a reasonable tradeoff.
	fmt.Fprintf(h, "%s\n", s.host)

	// Hash authentication credentials; this means that if we use a
	// different username/password we won't leak potentially sensitive
	// information.
	s.auth.WriteCacheKey(h)

	return fmt.Sprintf("%x", h.Sum(nil))
}

func (s *server) fetchInventory(ctx context.Context) (pveInventory, error) {
	// Start by fetching the list of nodes from the Proxmox API; if this
	// succeeds, then we continue.
	inventory, err := s.fetchInventoryFromProxmox(ctx)
	if err != nil {
		// If we have a cache and this is the first time we're trying to
		// fetch inventory, try loading it from the cache file.
		//
		// We only do this once to ensure that we're not loading the cache,
		// fetching an updated inventory from Proxmox, and then
		// re-loading the old and out-of-date cache again if the
		// Proxmox call fails.
		if s.cachePath != "" {
			var (
				loaded   bool
				cacheErr error
			)
			s.cacheLoadOnce.Do(func() {
				loaded = true
				inventory, cacheErr = s.loadCache()
				if cacheErr != nil {
					logger.Error("error loading inventory from cache", pvelog.Error(cacheErr))
				}
			})
			if loaded && cacheErr == nil {
				logger.Debug("loaded inventory from cache",
					slog.String("original_error", err.Error()),
				)
				return inventory, nil
			}
		}

		// If we don't have a cache, return the error.
		inventoryFetchErrors.Inc()
		return inventory, fmt.Errorf("fetching inventory from Proxmox: %w", err)
	}

	// We have a valid inventory; update metrics.
	//
	// TODO: do this in the "loaded from cache" path too?
	inventoryFetches.Inc()
	nodeCountMetric.Set(float64(len(inventory.NodeNames)))
	lxcCountMetric.Set(float64(CountSlice(inventory.Resources, func(item pveInventoryItem) bool {
		return item.Type == pveItemTypeLXC
	})))
	vmCountMetric.Set(float64(CountSlice(inventory.Resources, func(item pveInventoryItem) bool {
		return item.Type == pveItemTypeQEMU
	})))

	// On success, save the inventory to the cache.
	if s.cachePath != "" {
		if err := s.saveCache(inventory); err != nil {
			logger.Error("error saving inventory to cache", pvelog.Error(err))
			// continue; non-fatal
		}
	}

	// Update lastInventoryUpdate time now that we've fetched the
	// inventory.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastInventoryUpdate = time.Now()
	lastInventoryUpdateMetric.Set(float64(s.lastInventoryUpdate.Unix()))
	return inventory, nil
}

func (s *server) loadCache() (inventory pveInventory, err error) {
	if s.cachePath == "" {
		return inventory, nil
	}

	// Read the cache file and unmarshal it into the inventory struct.
	var zero pveInventory
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		return zero, fmt.Errorf("reading cache file: %w", err)
	}

	if err := json.Unmarshal(data, &inventory); err != nil {
		return zero, fmt.Errorf("unmarshalling cache file: %w", err)
	}

	// Check that the cache version is compatible with the current version.
	if inventory.Version != currentCacheVersion {
		return zero, fmt.Errorf("cache version %d is incompatible with current version %d", inventory.Version, currentCacheVersion)
	}

	// Check that the cache key matches.
	if want := s.inventoryCacheKey(); inventory.CacheKey != want {
		return zero, fmt.Errorf("cache key %q does not match expected key %q", inventory.CacheKey, want)
	}

	// Update the lastInventoryUpdate time to the file's modification time
	if fileInfo, statErr := os.Stat(s.cachePath); statErr == nil {
		s.mu.Lock()
		s.lastInventoryUpdate = fileInfo.ModTime()
		s.mu.Unlock()
	}

	return inventory, nil
}

func (s *server) saveCache(inventory pveInventory) error {
	if s.cachePath == "" {
		return nil
	}

	// Update the version of the inventory to the current version.
	inventory.Version = currentCacheVersion

	// Set cache key.
	inventory.CacheKey = s.inventoryCacheKey()

	// JSON-marshal the inventory, write it to a temporary file in the same
	// directory, and then atomically rename it.
	data, err := json.Marshal(inventory)
	if err != nil {
		return fmt.Errorf("marshalling inventory to JSON: %w", err)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(s.cachePath), "pve-inventory-*.json")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("writing temporary file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temporary file: %w", err)
	}

	if err := os.Rename(tmpFile.Name(), s.cachePath); err != nil {
		return fmt.Errorf("renaming temporary file: %w", err)
	}

	logger.Info("saved inventory to cache", slog.String("path", s.cachePath))
	return nil
}

func (s *server) fetchInventoryFromProxmox(ctx context.Context) (inventory pveInventory, _ error) {
	// Start by fetching the list of nodes from the Proxmox API
	nodes, err := s.client.GetNodes(ctx)
	if err != nil {
		return inventory, fmt.Errorf("fetching nodes: %w", err)
	}
	inventory.NodeStats = make(map[string]nodeInventoryStats, len(nodes))

	// For each node, fetch VMs and LXCs in parallel.
	var (
		g taskgroup.Group

		mu      sync.Mutex
		numLXCs int
		numVMs  int
	)
	for _, node := range nodes {
		// Save node name
		inventory.NodeNames = append(inventory.NodeNames, node.Node)

		g.Go(func() error {
			defer logger.Info("finished fetching inventory from node", "node", node.Node)
			nodeInventory, stats, err := s.fetchInventoryFromNode(ctx, node.Node)
			if err != nil {
				return err
			}

			mu.Lock()
			defer mu.Unlock()

			// Update resources
			inventory.NodeStats[node.Node] = stats
			inventory.Resources = append(inventory.Resources, nodeInventory.Resources...)

			// Update stats
			numLXCs += stats.NumLXCs
			numVMs += stats.NumVMs
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return inventory, fmt.Errorf("fetching inventory from nodes: %w", err)
	}

	logger.Debug("fetched inventory from Proxmox",
		"num_nodes", len(nodes),
		"num_vms", numVMs,
		"num_lxcs", numLXCs)

	return inventory, nil
}

func (s *server) fetchInventoryFromNode(ctx context.Context, node string) (inventory pveInventory, stats nodeInventoryStats, _ error) {
	logger := logger.With("node", node)

	// Fetch the list of VMs
	vms, err := s.client.GetQEMUVMs(ctx, node)
	if err != nil {
		return inventory, stats, fmt.Errorf("fetching VMs for node %q: %w", node, err)
	}
	stats.NumVMs = len(vms)

	// Add the VMs to the inventory
	for _, vm := range vms {
		// Skip VMs that are not running
		if vm.Status != "running" {
			continue
		}

		// Get the IP address of the VM
		addrs, err := s.fetchQEMUAddrs(ctx, node, vm.VMID)
		if err != nil {
			return inventory, stats, fmt.Errorf("fetching IP addresses for VM %q on %q: %w", vm.VMID, node, err)
		}
		logger.Debug("fetched IP addresses for VM", "vm", vm.Name, "addrs", addrs)

		inventory.Resources = append(inventory.Resources, pveInventoryItem{
			Name:  vm.Name,
			ID:    vm.VMID,
			Node:  node,
			Type:  pveItemTypeQEMU,
			Tags:  stringBoolMap(strings.Split(vm.Tags, ";")...),
			Addrs: addrs,
		})
	}

	// Fetch the list of LXCs
	lxcs, err := s.client.GetLXCs(ctx, node)
	if err != nil {
		return inventory, stats, fmt.Errorf("fetching LXCs for node %q: %w", node, err)
	}
	stats.NumLXCs = len(lxcs)

	// Add the LXCs to the inventory
	for _, lxc := range lxcs {
		// Skip LXCs that are not running
		if lxc.Status != "running" {
			continue
		}

		// Get the IP address of the VM
		addrs, err := s.fetchLXCAddrs(ctx, node, lxc.VMID)
		if err != nil {
			return inventory, stats, fmt.Errorf("fetching IP addresses for LXC %q on %q: %w", lxc.VMID, node, err)
		}
		logger.Debug("fetched IP addresses for LXC", "lxc", lxc.Name, "addrs", addrs)

		inventory.Resources = append(inventory.Resources, pveInventoryItem{
			Name:  lxc.Name,
			ID:    lxc.VMID,
			Node:  node,
			Type:  pveItemTypeLXC,
			Tags:  stringBoolMap(strings.Split(lxc.Tags, ";")...),
			Addrs: addrs,
		})
	}
	return inventory, stats, nil
}

func stringBoolMap(from ...string) map[string]bool {
	m := make(map[string]bool, len(from))
	for _, s := range from {
		m[s] = true
	}
	return m
}

func (s *server) fetchQEMUAddrs(ctx context.Context, node string, vmID int) ([]netip.Addr, error) {
	logger := logger.With("vm", vmID, "node", node)

	// Start by seeing if we can find a static IP address in the QEMU config.
	conf, err := s.client.GetQEMUConfig(ctx, node, vmID)
	if err != nil {
		return nil, fmt.Errorf("fetching QEMU config for %q on %q: %w", vmID, node, err)
	}

	// The ipconfig0 field is a comma-separated list of key-value pairs,
	// used to pass configuration to cloud-init; see the following for more
	// information:
	//    https://pve.proxmox.com/pve-docs/chapter-qm.html#qm_cloudinit
	//
	// Split and see if there's an "ip" key.
	ipConfig := splitKVs(conf.IPConfig0)
	if ip, ok := ipConfig["ip"]; ok {
		if pfx, err := netip.ParsePrefix(ip); err == nil {
			return []netip.Addr{pfx.Addr()}, nil
		} else {
			logger.Warn("error parsing static IP address",
				slog.String("address", ip),
				pvelog.Error(err))
		}
	}

	// Find the hardware address of all network interfaces specified in the
	// QEMU configuration.
	validHwaddrs := make(map[string]bool)
	for _, confstr := range conf.NetworkInterfaces {
		netConfig := splitKVs(confstr)

		for _, key := range []string{"macaddr", "virtio"} {
			if addr, ok := netConfig[key]; ok {
				// Store addresses as lowercase
				validHwaddrs[strings.ToLower(addr)] = true
				break
			}
		}
	}
	if len(validHwaddrs) == 0 {
		var attrs []any
		for ifname, confstr := range conf.NetworkInterfaces {
			attrs = append(attrs, slog.String("iface_"+ifname, confstr))
		}
		logger.Warn("no hardware address found for QEMU guest, returning all IP addresses", attrs...)
	}

	// Otherwise, fetch and return all non-localhost IP addresses from the QEMU guest, if any.
	interfaces, err := s.client.GetQEMUInterfaces(ctx, node, vmID)
	if err != nil {
		return nil, fmt.Errorf("fetching QEMU guest interfaces for %q on %q: %w", vmID, node, err)
	}
	logger.Debug("fetched QEMU guest interfaces", "num_interfaces", len(interfaces.Result))

	var addrs []netip.Addr
	for _, iface := range interfaces.Result {
		if iface.Name == "lo" {
			continue
		}

		// If we found any specified hardware addresses in our QEMU
		// configuration, only include addresses for those interfaces.
		lowerHwAddr := strings.ToLower(iface.HardwareAddress)
		if len(validHwaddrs) > 0 && !validHwaddrs[lowerHwAddr] {
			logger.Debug("skipping interface because the hardware address is unrecognized",
				slog.String("interface_name", iface.Name),
				slog.String("hardware_address", iface.HardwareAddress),
			)
			continue
		}

		for _, addr := range iface.IPAddresses {
			if addr.Type != "ipv4" && addr.Type != "ipv6" {
				continue
			}
			ip, err := netip.ParseAddr(addr.Address)
			if err != nil {
				logger.Error("parsing IP address", "address", addr.Address, pvelog.Error(err))
				continue
			}
			addrs = append(addrs, ip)
		}
	}
	return addrs, nil
}

func (s *server) fetchLXCAddrs(ctx context.Context, node string, vmID int) ([]netip.Addr, error) {
	logger := logger.With("lxc", vmID, "node", node)

	// Fetch the LXC guest config (to see if we can find a static IP address).
	conf, err := s.client.GetLXCConfig(ctx, node, vmID)
	if err != nil {
		return nil, fmt.Errorf("fetching LXC config for %q on %q: %w", vmID, node, err)
	}
	logger.Debug("fetched LXC config", "config", conf)

	// Fetch all interfaces from the LXC.
	interfaces, err := s.client.GetLXCInterfaces(ctx, node, vmID)
	if err != nil {
		return nil, fmt.Errorf("fetching LXC guest interfaces for %q on %q: %w", vmID, node, err)
	}
	logger.Debug("fetched LXC guest interfaces", "num_interfaces", len(interfaces))

	return extractLXCAddrs(ctx, logger, conf, interfaces)
}

func extractLXCAddrs(ctx context.Context, logger *slog.Logger, conf pveapi.LXCConfig, interfaces []pveapi.LXCInterface) ([]netip.Addr, error) {
	// The source of truth for what addresses a LXC can be reached by is
	// the 'interfaces' array, since that data comes from inside the LXC
	// itself. However, we can use the configuration to filter out
	// interfaces that aren't relevant to us (e.g. things created entirely
	// inside the LXC).
	//
	// This isn't the most optimal algorithm, and we do multiple passes
	// over the interfaces, but I'm hoping to make this as understandable
	// as possible given the various edge cases here.
	//
	// Start by parsing all LXC network configurations.
	configParsed := make(map[string]map[string]string)
	for ifname, confstr := range conf.NetworkInterfaces {
		configParsed[ifname] = splitKVs(confstr)
	}

	addrs := make(map[netip.Addr]bool)

	// Next: we want to drop any interface that doesn't have a hardware
	// address, since we can't match it to anything in the LXC
	// configuration. However, if there's a static IPv6 address in the LXC
	// configuration, we keep that address.
	//
	// This is because the interfaces response only contains a single IPv6
	// address (in LXCInterface.Inet6), which isn't always the same as the
	// static IPv6 address in the LXC configuration, and we can have both
	// addresses on the interface.
	//
	// At least anecdotally in my experience, Proxmox returns the IPv6
	// link-local address from the /interfaces endpoint, not a
	// statically-configured IPv6 address.
	configByHwaddr := make(map[string]map[string]string)
	for _, kvs := range configParsed {
		// Start by adding any valid IPv6 addresses from the LXC
		// configuration to our list of addresses.
		if ipv6, ok := kvs["ip6"]; ok {
			pfx, err := netip.ParsePrefix(ipv6)
			if err == nil {
				addrs[pfx.Addr()] = true
			} else {
				logger.Error("parsing static IPv6 address",
					slog.String("address", ipv6),
					pvelog.Error(err))
			}
		}

		// TODO: IPv4?

		// Now, if there's no hardware address we skip this interface.
		hwAddr := strings.ToLower(kvs["hwaddr"])
		if hwAddr == "" {
			continue
		}

		// Finally, build up the information about this interface,
		// keyed by hwaddr.
		configByHwaddr[hwAddr] = kvs
	}

	// Finally, iterate over all interfaces and add their addresses to our
	// list of addresses. If we have any hardware addresses in our LXC
	// configuration, only include addresses for those interfaces.
	for _, iface := range interfaces {
		if iface.Name == "lo" {
			continue
		}

		// If we found any specified hardware addresses in our LXC
		// configuration, only include addresses for those interfaces.
		lowerHwAddr := strings.ToLower(iface.HardwareAddress)
		if len(configByHwaddr) > 0 && configByHwaddr[lowerHwAddr] == nil {
			logger.Debug("skipping interface because the hardware address is unrecognized",
				slog.String("interface_name", iface.Name),
				slog.String("hardware_address", iface.HardwareAddress),
			)
			continue
		}

		// Great, now see if we can parse the IP address(es).
		if iface.Inet != "" {
			pref, err := netip.ParsePrefix(iface.Inet)
			if err != nil {
				logger.Error("parsing IP prefix", slog.String("prefix", iface.Inet), pvelog.Error(err))
			} else {
				addrs[pref.Addr()] = true
			}
		}
		if iface.Inet6 != "" {
			pref, err := netip.ParsePrefix(iface.Inet6)
			if err != nil {
				logger.Error("parsing IPv6 prefix", slog.String("prefix", iface.Inet6), pvelog.Error(err))
			} else {
				addrs[pref.Addr()] = true
			}
		}
	}

	// Great, all done! Return the list of addresses.
	addrsList := make([]netip.Addr, 0, len(addrs))
	for addr := range addrs {
		addrsList = append(addrsList, addr)
	}
	slices.SortFunc(addrsList, netip.Addr.Compare)
	return addrsList, nil
}

func splitKVs(s string) map[string]string {
	if len(s) == 0 {
		return nil
	}

	kvs := make(map[string]string)
	for _, kv := range strings.Split(s, ",") {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		kvs[key] = value
	}
	return kvs
}
