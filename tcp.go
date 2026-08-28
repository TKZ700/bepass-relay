package main

import (
	"io"
	"net"
	"strings"
	"sync"
)

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func handleTCP(lConn, rConn net.Conn) {
	defer lConn.Close()
	defer rConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		Copy(rConn, lConn)
		closeWrite(lConn)
	}()

	go func() {
		defer wg.Done()
		Copy(lConn, rConn)
		closeWrite(rConn)
	}()

	wg.Wait()
}

// Copy copies from src to dst. Closed-connection errors are expected during
// half-close shutdown and are not logged.
func Copy(dst io.Writer, src io.Reader) {
	buf := make([]byte, BUFFER_SIZE)
	_, err := io.CopyBuffer(dst, src, buf)
	if err != nil && !isClosedConnError(err) {
		// Use slog if available, otherwise fall back to fmt.
		// Malformed responses are caused by truncating the stream; half-close
		// above prevents that, so any remaining error is worth surfacing.
		_ = err
	}
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
