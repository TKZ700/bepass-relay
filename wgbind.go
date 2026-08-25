// wgbind.go implements a client-only conn.Bind that opens a single UDP socket
// whose address family matches the peer endpoint, instead of the wildcard
// IPv4+IPv6 socket pair opened by the stock bind. This keeps the relay from
// listening on an unnecessary v6 port and honors user-configured ports.
package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

type wgClientEndpoint struct {
	ap netip.AddrPort
}

func (e *wgClientEndpoint) ClearSrc()           {}
func (e *wgClientEndpoint) SrcToString() string { return "" }
func (e *wgClientEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *wgClientEndpoint) DstIP() netip.Addr   { return e.ap.Addr() }
func (e *wgClientEndpoint) DstToString() string { return e.ap.String() }

// DstToBytes is used for mac2 cookie calculations; any stable encoding of the
// destination address works.
func (e *wgClientEndpoint) DstToBytes() []byte {
	addr := e.ap.Addr().Unmap()
	var b [16]byte
	copy(b[:], addr.AsSlice())
	out := binary.BigEndian.AppendUint16(b[:], e.ap.Port())
	if !addr.Is4() {
		out = binary.BigEndian.AppendUint16(out, 0xffff)
	}
	return out
}

type wgClientBind struct {
	mu   sync.Mutex
	sock *net.UDPConn
	ep   *wgClientEndpoint
}

// newWGClientBind creates a bind whose socket family follows the resolved
// server endpoint (IPv4 unless the endpoint is genuinely IPv6).
func newWGClientBind(endpoint netip.AddrPort) *wgClientBind {
	return &wgClientBind{ep: &wgClientEndpoint{ap: endpoint}}
}

func (b *wgClientBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &wgClientEndpoint{ap: ap}, nil
}

func (b *wgClientBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.sock != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	family := "udp4"
	if addr := b.ep.ap.Addr(); addr.Is6() && !addr.Is4In6() {
		family = "udp6"
	}

	sock, err := net.ListenUDP(family, &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}

	b.sock = sock
	actualPort := uint16(sock.LocalAddr().(*net.UDPAddr).Port)

	return []conn.ReceiveFunc{b.receive}, actualPort, nil
}

func (b *wgClientBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	b.mu.Lock()
	sock := b.sock
	b.mu.Unlock()
	if sock == nil {
		return 0, net.ErrClosed
	}

	for {
		n, raddr, err := readFrom(sock, packets[0])
		if err != nil {
			return 0, err
		}
		// Some platforms report spurious zero-byte completions; ignore them.
		if n == 0 {
			continue
		}
		sizes[0] = n
		eps[0] = &wgClientEndpoint{
			ap: netip.AddrPortFrom(raddr.Addr().Unmap(), raddr.Port()),
		}
		return 1, nil
	}
}

// readFrom guards against a small race window in the standard library where
// ReadFromUDPAddrPort can panic while constructing its error value if the
// socket is closed concurrently with a failing read. Shutdown converts such
// panics into net.ErrClosed so receive loops terminate cleanly.
func readFrom(sock *net.UDPConn, b []byte) (n int, ap netip.AddrPort, err error) {
	defer func() {
		if r := recover(); r != nil {
			n, ap, err = 0, netip.AddrPort{}, net.ErrClosed
		}
	}()
	return sock.ReadFromUDPAddrPort(b)
}

func (b *wgClientBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	sock := b.sock
	b.mu.Unlock()
	if sock == nil {
		return errors.New("wireguard bind is not open")
	}

	dst, ok := ep.(*wgClientEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	for _, buf := range bufs {
		if _, err := sock.WriteToUDPAddrPort(buf, dst.ap); err != nil {
			return err
		}
	}
	return nil
}

func (b *wgClientBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.sock == nil {
		return nil
	}
	err := b.sock.Close()
	b.sock = nil
	return err
}

func (b *wgClientBind) SetMark(mark uint32) error {
	return nil
}

func (b *wgClientBind) BatchSize() int {
	return 1
}
