package main

import (
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func handleTCP(lConn, rConn net.Conn) {
	handleTCPWithLogger(nil, lConn, rConn, "", "")
}

func handleTCPWithLogger(l *slog.Logger, lConn, rConn net.Conn, remote, address string) {
	start := time.Now()
	if l != nil {
		l.Info("TCP relay started", "remote", remote, "address", address)
	}
	defer func() {
		if l != nil {
			l.Info("TCP relay finished", "remote", remote, "address", address, "duration", time.Since(start).String())
		}
		lConn.Close()
		rConn.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	var bytesAtoB, bytesBtoA int64

	go func() {
		defer wg.Done()
		n, _ := CopyWithBytes(rConn, lConn)
		bytesBtoA = n
		if l != nil {
			l.Debug("TCP direction finished", "direction", "remote->client", "remote", remote, "address", address, "bytes", n, "duration", time.Since(start).String())
		}
		closeWrite(lConn)
	}()

	go func() {
		defer wg.Done()
		n, _ := CopyWithBytes(lConn, rConn)
		bytesAtoB = n
		if l != nil {
			l.Debug("TCP direction finished", "direction", "client->remote", "remote", remote, "address", address, "bytes", n, "duration", time.Since(start).String())
		}
		closeWrite(rConn)
	}()

	wg.Wait()
	if l != nil {
		l.Info("TCP relay done", "remote", remote, "address", address, "bytes_client_to_remote", bytesAtoB, "bytes_remote_to_client", bytesBtoA, "duration", time.Since(start).String())
	}
}

// Copy copies from src to dst. Closed-connection errors are expected during
// half-close shutdown and are not logged.
func Copy(dst io.Writer, src io.Reader) {
	_, _ = CopyWithBytes(dst, src)
}

// CopyWithBytes copies and returns bytes written.
func CopyWithBytes(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, BUFFER_SIZE)
	n, err := io.CopyBuffer(dst, src, buf)
	if err != nil && !isClosedConnError(err) {
		// Half-close shutdown produces expected errors; real errors are ignored
		// here but counted via bytes. Callers can log if needed.
		_ = err
		return n, err
	}
	if isClosedConnError(err) {
		return n, nil
	}
	return n, err
}

func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset by peer")
}
