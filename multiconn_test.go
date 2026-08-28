package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestMultiConnReadsBufferedDataFirst(t *testing.T) {
	// Simulate what happens in handleConnection: a bufio.Reader reads ahead,
	// then we wrap the remainder + raw connection in a multiConn.
	rawData := []byte("tcp@1.2.3.4$80\rGET / HTTP/1.1\r\n")
	mock := &mockConn{reader: bytes.NewReader(rawData)}

	// Create a bufio.Reader wrapping the mock connection
	bufr := bufio.NewReader(mock)

	// Read the header (including the \r delimiter)
	header, err := bufr.ReadBytes('\r')
	if err != nil {
		t.Fatalf("unexpected error reading header: %v", err)
	}

	expectedHeader := "tcp@1.2.3.4$80\r"
	if string(header) != expectedHeader {
		t.Fatalf("header = %q, want %q", string(header), expectedHeader)
	}

	// Create multiConn with combined reader
	combinedReader := io.MultiReader(bufr, mock)
	mc := &multiConn{Reader: combinedReader, Conn: mock}

	// Read from multiConn — should get the remaining data that was buffered
	buf := make([]byte, 1024)
	n, err := mc.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("multiConn.Read error: %v", err)
	}

	remaining := "GET / HTTP/1.1\r\n"
	if string(buf[:n]) != remaining {
		t.Errorf("multiConn.Read = %q, want %q", string(buf[:n]), remaining)
	}
}

func TestMultiConnWritesToRawConn(t *testing.T) {
	mock := &mockConn{reader: bytes.NewReader(nil)}
	mc := &multiConn{Reader: bytes.NewReader(nil), Conn: mock}

	data := []byte("hello")
	n, err := mc.Write(data)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write n = %d, want %d", n, len(data))
	}
	if string(mock.written) != "hello" {
		t.Errorf("written = %q, want %q", string(mock.written), "hello")
	}
}

func TestMultiConnCloseDelegates(t *testing.T) {
	mock := &mockConn{reader: bytes.NewReader(nil)}
	mc := &multiConn{Reader: bytes.NewReader(nil), Conn: mock}

	err := mc.Close()
	if err != nil {
		t.Errorf("Close error: %v", err)
	}
	if !mock.closed {
		t.Error("Close did not delegate to underlying connection")
	}
}

func TestDstToBytesMatchesMarshalBinary(t *testing.T) {
	cases := []string{
		"192.0.2.1:51820",
		"10.0.0.1:12345",
		"[::1]:51820",
		"[2001:db8::1]:443",
	}
	for _, addrPort := range cases {
		ap := netip.MustParseAddrPort(addrPort)
		e := &wgClientEndpoint{ap: ap}

		got := e.DstToBytes()
		want, _ := ap.MarshalBinary()

		if !bytes.Equal(got, want) {
			t.Errorf("DstToBytes(%s) = %x, want %x", addrPort, got, want)
		}
	}
}

// mockConn is a minimal net.Conn for testing.
type mockConn struct {
	reader  io.Reader
	written []byte
	closed  bool
}

func (c *mockConn) Read(p []byte) (int, error)           { return c.reader.Read(p) }
func (c *mockConn) Write(p []byte) (int, error)          { c.written = append(c.written, p...); return len(p), nil }
func (c *mockConn) Close() error                         { c.closed = true; return nil }
func (c *mockConn) LocalAddr() net.Addr                  { return &net.TCPAddr{} }
func (c *mockConn) RemoteAddr() net.Addr                 { return &net.TCPAddr{} }
func (c *mockConn) SetDeadline(_ time.Time) error        { return nil }
func (c *mockConn) SetReadDeadline(_ time.Time) error    { return nil }
func (c *mockConn) SetWriteDeadline(_ time.Time) error   { return nil }
