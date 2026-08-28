// outbound.go abstracts how the relay reaches destinations so that different
// transports (direct dialing, userspace WireGuard) can be swapped in.
package main

import (
	"context"
	"log/slog"
	"net"
	"time"
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
	return &directOutbound{
		dialer: net.Dialer{Timeout: 15 * time.Second},
	}
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
	start := time.Now()
	conn, err := o.primary.DialContext(ctx, network, address)
	if err == nil {
		o.l.Info("outbound via wireguard",
			"protocol", network,
			"address", address,
			"duration", time.Since(start).String(),
		)
		return conn, nil
	}

	o.l.Warn("wireguard dial failed, falling back to direct",
		"protocol", network,
		"address", address,
		"error", err.Error(),
		"duration", time.Since(start).String(),
	)

	// If the original context was cancelled/timed-out during the WG
	// attempt, the fallback must use a fresh context or it will fail
	// instantly with the same deadline.
	fallbackCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		fallbackCtx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		o.l.Debug("using fresh context for fallback dial", "reason", ctx.Err().Error())
	}

	start2 := time.Now()
	fbConn, fbErr := o.fallback.DialContext(fallbackCtx, network, address)
	if fbErr != nil {
		o.l.Error("fallback direct dial also failed",
			"protocol", network,
			"address", address,
			"error", fbErr.Error(),
			"duration", time.Since(start2).String(),
		)
		return nil, fbErr
	}
	o.l.Info("outbound via direct (fallback)",
		"protocol", network,
		"address", address,
		"duration", time.Since(start2).String(),
	)
	return fbConn, nil
}

func (o *failoverOutbound) Close() error {
	err := o.primary.Close()
	if ferr := o.fallback.Close(); err == nil && ferr != nil {
		err = ferr
	}
	return err
}
