// Relay is a package that provides functionality for relaying network traffic.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

const BUFFER_SIZE = 2048

// multiConn wraps an io.Reader and a net.Conn so that reads go through the
// reader (which may contain buffered data from a prior bufio.Reader) while
// writes, deadlines, and Close delegate to the raw connection.
type multiConn struct {
	io.Reader
	net.Conn
}

func (c *multiConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

// readHeader reads a line terminated by \r, \n, or \r\n and returns the line
// without the delimiter. It is compatible with both the legacy relay protocol
// (\r) and the current bepass-worker (\r\n from `${mmd}\r\n`).
func readHeader(r *bufio.Reader) (string, error) {
	var buf []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			if len(buf) == 0 {
				return "", err
			}
			return strings.TrimSpace(string(buf)), nil
		}
		if b == '\r' {
			// Consume optional \n after \r
			if peek, _ := r.Peek(1); len(peek) == 1 && peek[0] == '\n' {
				_, _ = r.ReadByte()
			}
			return string(buf), nil
		}
		if b == '\n' {
			return string(buf), nil
		}
		buf = append(buf, b)
		// Guard against absurdly long header (DoS)
		if len(buf) > 2048 {
			return "", fmt.Errorf("header too long")
		}
	}
}

func (c *multiConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// buildOutbound constructs the outbound chain. Without a WireGuard config the
// relay dials directly; with one, every connection is attempted through the
// tunnel and falls back to direct dialing on failure.
func buildOutbound(l *slog.Logger, wgConfigPath string) (outbound, error) {
	direct := newDirectOutbound()
	if wgConfigPath == "" {
		return direct, nil
	}

	cfg, err := LoadWGConfig(wgConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load wireguard config: %w", err)
	}

	tunnel, err := newWireGuardOutbound(l, cfg)
	if err != nil {
		return nil, err
	}

	return newFailoverOutbound(l, tunnel, direct), nil
}

func run(ctx context.Context, l *slog.Logger, bind, wgConfigPath string) error {
	ob, err := buildOutbound(l, wgConfigPath)
	if err != nil {
		return err
	}
	defer ob.Close()

	if wgConfigPath != "" {
		l.Info("wireguard chaining enabled", "config", wgConfigPath)
	} else {
		l.Info("wireguard chaining disabled (direct outbound)")
	}

	listener, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	defer listener.Close()
	l.Info("relay listening", "bind", bind)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				l.Error("failed to accept connection", "error", err.Error())
				continue
			}

			src := netip.MustParseAddrPort(conn.RemoteAddr().String())

			// Check if srcIP is in the whitelist
			if !connFilter.isSourceAllowed(src.Addr()) {
				l.Debug("blocked connection", "address", src)
				conn.Close()
				continue
			}

			go handleConnection(l, ob, conn)
		}
	}
}

func handleConnection(l *slog.Logger, ob outbound, lConn net.Conn) {
	start := time.Now()
	remote := lConn.RemoteAddr().String()
	l.Info("new connection", "remote", remote)

	reader := bufio.NewReader(lConn)

	// Guard header read with a deadline so a stuck client can't hold the
	// goroutine forever. Worker sends header as `${net}@${host}$${port}\r\n`
	// (see bepass-worker src/worker.ts). Handle \r, \n, and \r\n.
	_ = lConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	headerStr, err := readHeader(reader)
	_ = lConn.SetReadDeadline(time.Time{})
	if err != nil {
		l.Warn("failed to read header", "remote", remote, "error", err.Error(), "duration", time.Since(start).String())
		lConn.Close()
		return
	}
	if headerStr == "" {
		l.Warn("empty header", "remote", remote, "duration", time.Since(start).String())
		lConn.Close()
		return
	}
	l.Debug("header received", "remote", remote, "raw", fmt.Sprintf("%q", headerStr), "duration", time.Since(start).String())

	inputHeader := strings.Split(headerStr, "@")
	if len(inputHeader) < 2 {
		l.Warn("invalid header format", "remote", remote, "header", fmt.Sprintf("%q", headerStr))
		lConn.Close()
		return
	}

	network := "tcp"
	if inputHeader[0] == "udp" {
		network = "udp"
	}

	address := strings.Replace(inputHeader[1], "$", ":", -1)
	dh, _, err := net.SplitHostPort(address)
	if err != nil {
		l.Warn("invalid address in header", "remote", remote, "address", address, "error", err.Error())
		lConn.Close()
		return
	}

	// check if ip is not blocked
	blockFlag := false
	addr, err := netip.ParseAddr(dh)
	if err != nil {
		// the host may not be an IP, try to resolve it (with DNS cache)
		var ips []net.IP
		if hostDNSCache != nil {
			if cached, ok := hostDNSCache.GetIPs(dh); ok {
				l.Debug("DNS cache hit (host)", "remote", remote, "host", dh, "ips", fmt.Sprint(cached))
				ips = cached
			}
		}
		if ips == nil {
			l.Debug("resolving destination host", "remote", remote, "host", dh)
			lookupStart := time.Now()
			ips, err = net.LookupIP(dh)
			if err != nil {
				l.Warn("failed to resolve destination", "remote", remote, "host", dh, "error", err.Error(), "duration", time.Since(start).String())
				lConn.Close()
				return
			}
			l.Debug("destination resolved", "remote", remote, "host", dh, "ip", ips[0].String(), "duration", time.Since(lookupStart).String())
			if hostDNSCache != nil {
				hostDNSCache.SetIPs(dh, ips)
			}
		}

		// parse the first IP and use it
		addr, _ = netip.AddrFromSlice(ips[0])
	}

	// If the address is invalid or not allowed as a destination, set the block flag.
	blockFlag = !addr.IsValid() || !connFilter.isDestinationAllowed(addr)

	if blockFlag {
		l.Warn("destination host is blocked", "remote", remote, "address", address)
		lConn.Close()
		return
	}

	// Preserve any bytes already buffered by the bufio.Reader. Using the
	// reader itself for subsequent reads guarantees no data after the header
	// is lost, even when the header and payload arrived in one segment.
	mc := &multiConn{Reader: reader, Conn: lConn}

	l.Info("dialing destination", "remote", remote, "protocol", network, "address", address)
	dialStart := time.Now()

	switch network {
	case "tcp":
		rConn, err := ob.DialContext(context.Background(), network, address)
		if err != nil {
			l.Error("failed to dial", "remote", remote, "protocol", network, "address", address, "error", err.Error(), "duration", time.Since(dialStart).String(), "total", time.Since(start).String())
			lConn.Close()
			return
		}
		l.Info("dial succeeded, starting relay", "remote", remote, "protocol", network, "address", address, "duration", time.Since(dialStart).String(), "total", time.Since(start).String())

		go handleTCPWithLogger(l, mc, rConn, remote, address)

	case "udp":
		l.Info("starting UDP over TCP relay", "remote", remote, "address", address, "duration", time.Since(dialStart).String())
		go handleUDPOverTCP(l, ob, mc, address)
	}
	l.Debug("relaying connection", "remote", remote, "protocol", network, "address", address, "duration", time.Since(start).String())
}



func main() {
	fs := ff.NewFlagSet("bepass-relay")
	var (
		verbose      = fs.Bool('v', "verbose", "enable verbose logging")
		bind         = fs.String('b', "bind", "0.0.0.0:6666", "bind address")
		wgConfPath   = fs.String('w', "wg-config", "", "path to WireGuard config file (enables WireGuard outbound)")
		dnsCacheTTL  = fs.Duration(0, "dns-cache-ttl", 60*time.Second, "DNS cache TTL (0 to disable)")
		dnsCacheSize = fs.Int(0, "dns-cache-size", 512, "DNS cache max entries")
	)

	err := ff.Parse(fs, os.Args[1:])
	switch {
	case errors.Is(err, ff.ErrHelp):
		fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Flags(fs))
		os.Exit(0)
	case err != nil:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *verbose {
		l = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	if *dnsCacheTTL > 0 && *dnsCacheSize > 0 {
		hostDNSCache = NewDNSCache(*dnsCacheTTL, *dnsCacheSize)
		tunnelDNSCache = NewDNSCache(*dnsCacheTTL, *dnsCacheSize)
		l.Info("DNS cache enabled", "ttl", dnsCacheTTL.String(), "size", *dnsCacheSize)
	} else {
		l.Info("DNS cache disabled")
	}

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if err := run(ctx, l, *bind, *wgConfPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	<-ctx.Done()
}
