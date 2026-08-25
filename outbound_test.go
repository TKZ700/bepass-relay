package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type stubOutbound struct {
	dialErr error
	conns   []net.Conn
	dials   int
	closed  bool
}

func (o *stubOutbound) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	o.dials++
	if o.dialErr != nil {
		return nil, o.dialErr
	}
	c1, c2 := net.Pipe()
	o.conns = append(o.conns, c1)
	return c2, nil
}

func (o *stubOutbound) Close() error {
	o.closed = true
	return nil
}

func TestDirectOutboundDials(t *testing.T) {
	ob := newDirectOutbound()
	conn, err := ob.DialContext(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		conn.Close()
	}
	// Connection to port 1 may or may not succeed depending on the host;
	// we only verify the call path doesn't panic and Close is a no-op.
	if err := ob.Close(); err != nil {
		t.Errorf("close returned error: %v", err)
	}
}

func TestFailoverPrimarySuccess(t *testing.T) {
	primary := &stubOutbound{}
	fallback := &stubOutbound{}
	ob := newFailoverOutbound(discardLogger(), primary, fallback)

	conn, err := ob.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	conn.Close()

	if fallback.dials != 0 {
		t.Errorf("fallback dialed %d times, want 0", fallback.dials)
	}
}

func TestFailoverFallsBackOnError(t *testing.T) {
	primary := &stubOutbound{dialErr: errors.New("tunnel down")}
	fallback := &stubOutbound{}
	ob := newFailoverOutbound(discardLogger(), primary, fallback)

	conn, err := ob.DialContext(context.Background(), "udp", "example.com:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	conn.Close()

	if primary.dials != 1 || fallback.dials != 1 {
		t.Errorf("primary dials=%d fallback dials=%d, want 1/1", primary.dials, fallback.dials)
	}
}

func TestFailoverClosePropagates(t *testing.T) {
	primary := &stubOutbound{}
	fallback := &stubOutbound{}
	ob := newFailoverOutbound(discardLogger(), primary, fallback)

	if err := ob.Close(); err != nil {
		t.Fatalf("close returned error: %v", err)
	}
	if !primary.closed || !fallback.closed {
		t.Errorf("primary.closed=%v fallback.closed=%v, want both true", primary.closed, fallback.closed)
	}
}
