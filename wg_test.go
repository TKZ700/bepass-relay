package main

import (
	"context"
	"strings"
	"testing"
)

func TestWgKeyHexRoundTrip(t *testing.T) {
	hexStr, err := wgKeyHex(testPrivKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hexStr) != 64 {
		t.Fatalf("hex key length = %d, want 64", len(hexStr))
	}
	want := "0101010101010101010101010101010101010101010101010101010101010101"
	if hexStr != want {
		t.Errorf("hex = %s, want %s", hexStr, want)
	}

	if _, err := wgKeyHex("not-a-key"); err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestBuildIPCConfigFull(t *testing.T) {
	cfg, err := ParseWGConfig(strings.NewReader(fullTestConfig()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ipc, err := buildIPCConfig(cfg, "203.0.113.7:51820")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, want := range []string{
		"private_key=0101010101010101010101010101010101010101010101010101010101010101",
		"public_key=0202020202020202020202020202020202020202020202020202020202020202",
		"preshared_key=0303030303030303030303030303030303030303030303030303030303030303",
		"endpoint=203.0.113.7:51820",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"persistent_keepalive_interval=25",
	} {
		if !strings.Contains(ipc, want) {
			t.Errorf("IPC config missing %q:\n%s", want, ipc)
		}
	}
	if strings.Contains(ipc, "listen_port") {
		t.Error("listen_port should be omitted when unset")
	}
}

func TestBuildIPCConfigMinimal(t *testing.T) {
	conf := "[Interface]\nPrivateKey = " + testPrivKey + "\nAddress = 10.0.0.2\nListenPort = 4444\n" +
		"[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.1:51820\n"

	cfg, err := ParseWGConfig(strings.NewReader(conf))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ipc, err := buildIPCConfig(cfg, "192.0.2.1:51820")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(ipc, "listen_port=4444") {
		t.Error("listen_port missing")
	}
	if strings.Contains(ipc, "preshared_key") {
		t.Error("preshared_key should be omitted when unset")
	}
	if strings.Contains(ipc, "persistent_keepalive") {
		t.Error("persistent_keepalive should be omitted when zero")
	}
}

func TestResolveUDPEndpointIPPassthrough(t *testing.T) {
	got, err := resolveUDPEndpoint("192.0.2.1:51820")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "192.0.2.1:51820" {
		t.Errorf("got %q", got)
	}
}

func TestResolveUDPEndpointInvalid(t *testing.T) {
	for _, endpoint := range []string{"no-port-here", ":51820", "192.0.2.1:", "192.0.2.1:notaport"} {
		if _, err := resolveUDPEndpoint(endpoint); err == nil {
			t.Errorf("expected error for endpoint %q", endpoint)
		}
	}
}

// TestNewWireGuardOutboundSmoke verifies that the userspace device can be
// constructed from a parsed config without any network activity (the bind is
// only opened on first use).
func TestNewWireGuardOutboundSmoke(t *testing.T) {
	conf := "[Interface]\nPrivateKey = " + testPrivKey + "\nAddress = 10.66.66.2/24\n" +
		"[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.1:51820\n"

	cfg, err := ParseWGConfig(strings.NewReader(conf))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	ob, err := newWireGuardOutbound(discardLogger(), cfg)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	defer ob.Close()

	// Unsupported networks must fail fast without touching the tunnel.
	if _, err := ob.DialContext(context.Background(), "unix", "/tmp/sock"); err == nil {
		t.Error("expected error for unsupported network")
	}

	// Invalid destinations must fail fast as well.
	if _, err := ob.DialContext(context.Background(), "tcp", "no-port"); err == nil {
		t.Error("expected error for invalid destination")
	}
}
