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
		"listen_port", cfg.ListenPort,
	)
	l.Info("wireguard will be brought up on first dial; run with -v to see handshake logs (look for 'Handshake did not complete' or 'Received handshake response')")
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

	o.l.Debug("wireguard dial start", "protocol", network, "address", address)

	if err := o.ensureUp(); err != nil {
		o.l.Error("wireguard device not up", "protocol", network, "address", address, "error", err.Error())
		return nil, err
	}

	raddr, err := o.resolveAddrPort(ctx, address)
	if err != nil {
		o.l.Warn("wireguard resolve failed", "protocol", network, "address", address, "error", err.Error())
		return nil, err
	}
	o.l.Debug("wireguard resolved", "protocol", network, "address", address, "resolved", raddr.String())

	if network == "tcp" {
		start := time.Now()
		dialCtx, cancel := context.WithTimeout(ctx, wgDialTimeout)
		defer cancel()
		conn, err := o.tnet.DialContextTCPAddrPort(dialCtx, raddr)
		if err != nil {
			o.l.Warn("wireguard tunnel dial failed", "protocol", network, "address", address, "resolved", raddr.String(), "error", err.Error(), "duration", time.Since(start).String())
			// Hint about common causes.
			if isTimeout(err) {
				o.l.Warn("wireguard tunnel dial timed out – handshake likely did not complete; check server AllowedIPs, firewall/UDP blocking, and run with -v for handshake logs")
			}
			return nil, fmt.Errorf("tunnel dial %s: %w", raddr, err)
		}
		o.l.Debug("wireguard tunnel dial succeeded", "protocol", network, "address", address, "resolved", raddr.String(), "duration", time.Since(start).String())
		return conn, nil
	}

	start := time.Now()
	conn, err := o.tnet.DialUDPAddrPort(netip.AddrPort{}, raddr)
	if err != nil {
		o.l.Warn("wireguard tunnel dial failed", "protocol", network, "address", address, "resolved", raddr.String(), "error", err.Error(), "duration", time.Since(start).String())
		return nil, err
	}
	o.l.Debug("wireguard tunnel dial succeeded", "protocol", network, "address", address, "resolved", raddr.String(), "duration", time.Since(start).String())
	return conn, nil
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if err.Error() == "context deadline exceeded" {
		return true
	}
	//net.Error with Timeout() true
	type timeoutErr interface{ Timeout() bool }
	if te, ok := err.(timeoutErr); ok && te.Timeout() {
		return true
	}
	return false
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

	o.l.Info("bringing wireguard device up")
	start := time.Now()
	if err := o.dev.Up(); err != nil {
		o.upErr = fmt.Errorf("bring up wireguard device: %w", err)
		o.upFailedAt = time.Now()
		o.l.Error("wireguard device up failed", "error", o.upErr.Error(), "duration", time.Since(start).String())
		return o.upErr
	}

	o.devUp = true
	o.upErr = nil
	o.l.Info("wireguard device is up", "duration", time.Since(start).String())
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
	o.l.Debug("wireguard DNS lookup via tunnel", "host", host)
	dnsCtx, cancel := context.WithTimeout(ctx, wgDNSTimeout)
	defer cancel()
	start := time.Now()
	addrs, err := o.tnet.LookupContextHost(dnsCtx, host)
	if err != nil {
		o.l.Warn("wireguard DNS lookup failed", "host", host, "error", err.Error(), "duration", time.Since(start).String())
		return netip.AddrPort{}, fmt.Errorf("resolve %q through tunnel: %w", host, err)
	}
	o.l.Debug("wireguard DNS lookup succeeded", "host", host, "addrs", fmt.Sprint(addrs), "duration", time.Since(start).String())

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
