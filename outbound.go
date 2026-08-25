// outbound.go abstracts how the relay reaches destinations so that different
// transports (direct dialing, userspace WireGuard) can be swapped in.
package main

import (
	"context"
	"log/slog"
	"net"
)

// outbound dials connections to a destination address ("host:port").
type outbound interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Close() error
}

// directOutbound dials destinations directly using the host network stack.
type directOutbound struct {
	dialer net.Dialer
}

func newDirectOutbound() *directOutbound {
	return &directOutbound{}
}

func (o *directOutbound) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return o.dialer.DialContext(ctx, network, address)
}

func (o *directOutbound) Close() error {
	return nil
}

// failoverOutbound tries primary first and silently falls back to fallback
// when the primary dial fails.
type failoverOutbound struct {
	l        *slog.Logger
	primary  outbound
	fallback outbound
}

func newFailoverOutbound(l *slog.Logger, primary, fallback outbound) *failoverOutbound {
	return &failoverOutbound{l: l, primary: primary, fallback: fallback}
}

func (o *failoverOutbound) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := o.primary.DialContext(ctx, network, address)
	if err == nil {
		return conn, nil
	}
	o.l.Debug("wireguard outbound failed, falling back to direct dial",
		"protocol", network,
		"address", address,
		"error", err.Error(),
	)
	return o.fallback.DialContext(ctx, network, address)
}

func (o *failoverOutbound) Close() error {
	err := o.primary.Close()
	if ferr := o.fallback.Close(); err == nil && ferr != nil {
		err = ferr
	}
	return err
}
