// wg.go implements an outbound that tunnels every connection through a
// WireGuard server using the userspace wireguard-go stack (no TUN device).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	wgDefaultDNS   = "1.1.1.1"
	wgDialTimeout  = 10 * time.Second
	wgDNSTimeout   = 5 * time.Second
)

type wireGuardOutbound struct {
	l          *slog.Logger
	dev        *device.Device
	tnet       *netstack.Net
	localAddrs []netip.Addr
	mu         sync.Mutex
	devUp      bool
	upErr      error
	upFailedAt time.Time
}

const wgUpRetryCooldown = 30 * time.Second

func newWireGuardOutbound(l *slog.Logger, cfg *wgConfig) (*wireGuardOutbound, error) {
	endpoint, err := resolveUDPEndpoint(cfg.Peer.Endpoint)
	if err != nil {
		return nil, err
	}

	ipc, err := buildIPCConfig(cfg, endpoint.String())
	if err != nil {
		return nil, err
	}

	localAddrs := make([]netip.Addr, 0, len(cfg.Addresses))
	for _, p := range cfg.Addresses {
		localAddrs = append(localAddrs, p.Addr())
	}

	dnsServers := cfg.DNS
	if len(dnsServers) == 0 {
		dnsServers = []netip.Addr{netip.MustParseAddr(wgDefaultDNS)}
	}

	tunDev, tnet, err := netstack.CreateNetTUN(localAddrs, dnsServers, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create wireguard network stack: %w", err)
	}

	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			l.Debug("wireguard: " + fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			l.Error("wireguard: " + fmt.Sprintf(format, args...))
		},
	}

	dev := device.NewDevice(tunDev, newWGClientBind(endpoint), logger)

	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, fmt.Errorf("apply wireguard config: %w", err)
	}

	o := &wireGuardOutbound{l: l, dev: dev, tnet: tnet, localAddrs: localAddrs}
	l.Info("wireguard outbound configured",
		"endpoint", endpoint,
		"local_addresses", fmt.Sprint(localAddrs),
		"dns", fmt.Sprint(dnsServers),
		"mtu", cfg.MTU,
	)
	return o, nil
}

// DialContext connects to address through the WireGuard tunnel. Hostnames are
// resolved through the tunnel's DNS servers so lookups never leak locally.
func (o *wireGuardOutbound) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "udp":
	default:
		return nil, fmt.Errorf("unsupported network %q for wireguard outbound", network)
	}

	if err := o.ensureUp(); err != nil {
		return nil, err
	}

	raddr, err := o.resolveAddrPort(ctx, address)
	if err != nil {
		return nil, err
	}

	if network == "tcp" {
		dialCtx, cancel := context.WithTimeout(ctx, wgDialTimeout)
		defer cancel()
		conn, err := o.tnet.DialContextTCPAddrPort(dialCtx, raddr)
		if err != nil {
			return nil, fmt.Errorf("tunnel dial %s: %w", raddr, err)
		}
		return conn, nil
	}
	return o.tnet.DialUDPAddrPort(netip.AddrPort{}, raddr)
}

// Close shuts down the tunnel device. Safe to call multiple times.
func (o *wireGuardOutbound) Close() error {
	o.dev.Close()
	return nil
}

// ensureUp brings the device up on first use. A failed attempt is cached for
// wgUpRetryCooldown before being retried, so transient failures don't
// permanently disable the tunnel.
func (o *wireGuardOutbound) ensureUp() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.devUp {
		return nil
	}
	if o.upErr != nil && time.Since(o.upFailedAt) < wgUpRetryCooldown {
		return o.upErr
	}

	if err := o.dev.Up(); err != nil {
		o.upErr = fmt.Errorf("bring up wireguard device: %w", err)
		o.upFailedAt = time.Now()
		return o.upErr
	}

	o.devUp = true
	o.upErr = nil
	return nil
}

func (o *wireGuardOutbound) resolveAddrPort(ctx context.Context, address string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid destination %q: %w", address, err)
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid destination port %q", portStr)
	}

	addr, err := netip.ParseAddr(host)
	if err == nil {
		return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
	}

	// Not an IP literal; resolve through the tunnel's DNS servers.
	dnsCtx, cancel := context.WithTimeout(ctx, wgDNSTimeout)
	defer cancel()
	addrs, err := o.tnet.LookupContextHost(dnsCtx, host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %q through tunnel: %w", host, err)
	}

	chosen, ok := pickFamilyMatch(o.localAddrs, addrs)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("no usable addresses for %q", host)
	}
	return netip.AddrPortFrom(chosen.Unmap(), uint16(port)), nil
}

// pickFamilyMatch prefers candidates whose IP family matches one of the
// tunnel's local addresses, falling back to the first candidate.
func pickFamilyMatch(local []netip.Addr, candidates []string) (netip.Addr, bool) {
	hasV4, hasV6 := false, false
	for _, a := range local {
		if a.Is4() {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}

	for _, c := range candidates {
		a, err := netip.ParseAddr(c)
		if err != nil {
			continue
		}
		if (a.Is4() && hasV4) || (!a.Is4() && hasV6) {
			return a, true
		}
	}

	if len(candidates) > 0 {
		a, err := netip.ParseAddr(candidates[0])
		if err == nil {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// resolveUDPEndpoint resolves the peer endpoint hostname using the host
// resolver at startup, since the bind layer only accepts ip:port endpoints.
// IPv4 results are preferred so the client bind opens a single v4 socket even
// on hosts with broken or disabled IPv6.
func resolveUDPEndpoint(endpoint string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid wireguard endpoint %q: %w", endpoint, err)
	}

	pnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil || pnum == 0 {
		return netip.AddrPort{}, fmt.Errorf("invalid wireguard endpoint port %q", port)
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		addrs, err := net.DefaultResolver.LookupHost(context.Background(), host)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("resolve wireguard endpoint %q: %w", host, err)
		}
		addr, err = pickPreferredAddr(addrs)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("resolve wireguard endpoint %q: %w", host, err)
		}
	}

	return netip.AddrPortFrom(addr.Unmap(), uint16(pnum)), nil
}

func pickPreferredAddr(addrs []string) (netip.Addr, error) {
	for _, s := range addrs {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			return a, nil
		}
	}
	for _, s := range addrs {
		if a, err := netip.ParseAddr(s); err == nil {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no usable addresses")
}
