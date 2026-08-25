package main

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func TestWgClientBindRoundTrip(t *testing.T) {
	a := newWGClientBind(netip.MustParseAddrPort("127.0.0.1:1"))
	b := newWGClientBind(netip.MustParseAddrPort("127.0.0.1:1"))
	defer a.Close()
	defer b.Close()

	fnsA, portA, err := a.Open(0)
	if err != nil {
		t.Fatalf("bind a open: %v", err)
	}
	if len(fnsA) != 1 {
		t.Fatalf("expected a single receive func, got %d", len(fnsA))
	}

	fnsB, portB, err := b.Open(0)
	if err != nil {
		t.Fatalf("bind b open: %v", err)
	}

	if portA == 0 || portB == 0 {
		t.Fatalf("expected ephemeral ports, got %d and %d", portA, portB)
	}

	type recvResult struct {
		n   int
		ep  conn.Endpoint
		err error
	}
	packets := [][]byte{make([]byte, 65535)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	resultCh := make(chan recvResult, 1)
	go func() {
		n, err := fnsB[0](packets, sizes, eps)
		var ep conn.Endpoint
		if n > 0 {
			ep = eps[0]
		}
		resultCh <- recvResult{n: n, ep: ep, err: err}
	}()

	payload := []byte("handshake-initiation-test")
	if err := a.Send([][]byte{payload}, &wgClientEndpoint{ap: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(portB))}); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("receive error: %v", res.err)
		}
		if string(packets[0][:sizes[0]]) != string(payload) {
			t.Errorf("payload mismatch")
		}
		wep, ok := res.ep.(*wgClientEndpoint)
		if !ok {
			t.Fatalf("unexpected endpoint type %T", res.ep)
		}
		if wep.ap.Addr() != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("source addr = %v", wep.ap.Addr())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for datagram")
	}
}

func TestWgClientBindCloseReleasesReceive(t *testing.T) {
	b := newWGClientBind(netip.MustParseAddrPort("127.0.0.1:1"))
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 65535)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		_, err := fns[0](bufs, sizes, eps)
		errCh <- err
	}()

	time.Sleep(100 * time.Millisecond)
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("receive error after close = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receive did not return after close")
	}
}

func TestWgClientBindOpenTwiceFails(t *testing.T) {
	b := newWGClientBind(netip.MustParseAddrPort("127.0.0.1:1"))
	defer b.Close()

	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, _, err := b.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("second open error = %v, want ErrBindAlreadyOpen", err)
	}
}

func TestWgClientEndpointDstToBytesStable(t *testing.T) {
	e1 := &wgClientEndpoint{ap: netip.MustParseAddrPort("192.0.2.1:51820")}
	e2 := &wgClientEndpoint{ap: netip.MustParseAddrPort("192.0.2.1:51820")}
	if string(e1.DstToBytes()) != string(e2.DstToBytes()) {
		t.Error("DstToBytes not stable for equal endpoints")
	}
	if e1.DstToString() != "192.0.2.1:51820" {
		t.Errorf("DstToString = %q", e1.DstToString())
	}
	if !e1.DstIP().Is4() {
		t.Errorf("DstIP = %v", e1.DstIP())
	}
}
