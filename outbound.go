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
	// Happy-eyeballs style: race wireguard vs direct, prefer wireguard if it
	// wins quickly, otherwise use direct. This hides the 5s WG timeout on
	// first load where the handshake is still warming up.
	type result struct {
		conn net.Conn
		err  error
	}

	wgCh := make(chan result, 1)
	directCh := make(chan result, 1)

	wgCtx, wgCancel := context.WithTimeout(ctx, 3*time.Second)
	defer wgCancel()

	go func() {
		c, err := o.primary.DialContext(wgCtx, network, address)
		wgCh <- result{c, err}
	}()

	// Give wireguard a 400ms head-start before racing direct. For the common
	// case where WG is healthy, it wins and we avoid an extra direct socket.
	go func() {
		select {
		case <-time.After(400 * time.Millisecond):
		case <-ctx.Done():
			directCh <- result{nil, ctx.Err()}
			return
		}
		// Direct dial must not inherit the WG timeout.
		dCtx := ctx
		if ctx.Err() != nil {
			var cancel context.CancelFunc
			dCtx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
		}
		c, err := o.fallback.DialContext(dCtx, network, address)
		directCh <- result{c, err}
	}()

	// Wait for wireguard first.
	select {
	case r := <-wgCh:
		if r.err == nil {
			// WG won – close the direct loser if it arrives later.
			go func() {
				if dr := <-directCh; dr.conn != nil {
					dr.conn.Close()
				}
			}()
			o.l.Info("outbound via wireguard",
				"protocol", network,
				"address", address,
			)
			return r.conn, nil
		}
		o.l.Debug("wireguard dial failed, waiting for direct",
			"protocol", network,
			"address", address,
			"error", r.err.Error(),
		)
		// WG failed – wait for direct.
		dr := <-directCh
		if dr.err != nil {
			o.l.Error("direct dial also failed",
				"protocol", network,
				"address", address,
				"error", dr.err.Error(),
			)
			return nil, dr.err
		}
		o.l.Info("outbound via direct (wireguard failed)",
			"protocol", network,
			"address", address,
		)
		return dr.conn, nil
	case dr := <-directCh:
		// Direct won before WG (WG head-start expired and direct was faster).
		// Still wait a bit for WG in case it was just about to succeed.
		if dr.err == nil {
			select {
			case r := <-wgCh:
				if r.err == nil {
					dr.conn.Close()
					o.l.Info("outbound via wireguard (direct raced but WG won late)",
						"protocol", network,
						"address", address,
					)
					return r.conn, nil
				}
			case <-time.After(100 * time.Millisecond):
			}
			o.l.Info("outbound via direct (raced)",
				"protocol", network,
				"address", address,
			)
			// Drain WG result to avoid goroutine leak.
			go func() {
				if r := <-wgCh; r.conn != nil {
					r.conn.Close()
				}
			}()
			return dr.conn, nil
		}
		// Direct failed – wait for WG.
		r := <-wgCh
		if r.err == nil {
			o.l.Info("outbound via wireguard (direct failed)",
				"protocol", network,
				"address", address,
			)
			return r.conn, nil
		}
		o.l.Error("both wireguard and direct dials failed",
			"protocol", network,
			"address", address,
			"wireguard_error", r.err.Error(),
			"direct_error", dr.err.Error(),
		)
		return nil, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (o *failoverOutbound) Close() error {
	err := o.primary.Close()
	if ferr := o.fallback.Close(); err == nil && ferr != nil {
		err = ferr
	}
	return err
}
