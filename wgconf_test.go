package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

var (
	testPrivKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))
	testPubKey  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, 32))
	testPSK     = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x03}, 32))
)

func fullTestConfig() string {
	return "[Interface]\n" +
		"PrivateKey = " + testPrivKey + "\n" +
		"Address = 10.66.66.2/24, fd42::2/128\n" +
		"DNS = 1.1.1.1, 8.8.8.8\n" +
		"MTU = 1380\n" +
		"\n" +
		"# a comment\n" +
		"[Peer]\n" +
		"PublicKey = " + testPubKey + "\n" +
		"PresharedKey = " + testPSK + "\n" +
		"Endpoint = vpn.example.com:51820\n" +
		"AllowedIPs = 10.0.0.0/8, ::/0\n" +
		"PersistentKeepalive = 25\n"
}

func TestParseWGConfigFull(t *testing.T) {
	cfg, err := ParseWGConfig(strings.NewReader(fullTestConfig()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.PrivateKey != testPrivKey {
		t.Errorf("private key mismatch")
	}
	if len(cfg.Addresses) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(cfg.Addresses))
	}
	if cfg.Addresses[0].String() != "10.66.66.2/24" {
		t.Errorf("address[0] = %s", cfg.Addresses[0])
	}
	if cfg.Addresses[1].String() != "fd42::2/128" {
		t.Errorf("address[1] = %s", cfg.Addresses[1])
	}
	if len(cfg.DNS) != 2 || cfg.DNS[0].String() != "1.1.1.1" || cfg.DNS[1].String() != "8.8.8.8" {
		t.Errorf("dns = %v", cfg.DNS)
	}
	if cfg.MTU != 1380 {
		t.Errorf("mtu = %d", cfg.MTU)
	}
	if cfg.Peer.PublicKey != testPubKey {
		t.Errorf("peer public key mismatch")
	}
	if cfg.Peer.PresharedKey != testPSK {
		t.Errorf("preshared key mismatch")
	}
	if cfg.Peer.Endpoint != "vpn.example.com:51820" {
		t.Errorf("endpoint = %s", cfg.Peer.Endpoint)
	}
	if cfg.Peer.PersistentKeepalive != 25 {
		t.Errorf("keepalive = %d", cfg.Peer.PersistentKeepalive)
	}
}

func TestParseWGConfigDefaults(t *testing.T) {
	conf := "[Interface]\n" +
		"PrivateKey = " + testPrivKey + "\n" +
		"Address = 10.0.0.2\n" +
		"[Peer]\n" +
		"PublicKey = " + testPubKey + "\n" +
		"Endpoint = 192.0.2.1:51820\n"

	cfg, err := ParseWGConfig(strings.NewReader(conf))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MTU != wgDefaultMTU {
		t.Errorf("default mtu = %d, want %d", cfg.MTU, wgDefaultMTU)
	}
	if len(cfg.DNS) != 0 {
		t.Errorf("dns should default to empty, got %v", cfg.DNS)
	}
	if cfg.ListenPort != 0 {
		t.Errorf("listen port should default to 0, got %d", cfg.ListenPort)
	}
	if cfg.Peer.PersistentKeepalive != 0 {
		t.Errorf("keepalive should default to 0, got %d", cfg.Peer.PersistentKeepalive)
	}
	if len(cfg.Addresses) != 1 || cfg.Addresses[0].Bits() != 32 {
		t.Errorf("bare address should get full prefix bits: %s", cfg.Addresses)
	}
}

func TestParseWGConfigCRLFAndCaseInsensitive(t *testing.T) {
	conf := strings.ReplaceAll(
		"[INTERFACE]\r\nPRIVATEKEY = "+testPrivKey+"\r\nADDRESS = 10.0.0.2\r\n"+
			"[Peer]\r\nPUBLICKEY = "+testPubKey+"\r\nENDPOINT = 192.0.2.1:51820\r\n",
		"\n", "\r\n")

	if _, err := ParseWGConfig(strings.NewReader(conf)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseWGConfigAllowedIPsIgnored(t *testing.T) {
	conf := "[Interface]\nPrivateKey = " + testPrivKey + "\nAddress = 10.0.0.2\n" +
		"[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.1:51820\n" +
		"AllowedIPs = 192.168.1.0/24\n"

	cfg, err := ParseWGConfig(strings.NewReader(conf))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Peer.Endpoint == "" {
		t.Fatal("endpoint lost")
	}
}

func TestParseWGConfigErrors(t *testing.T) {
	cases := []struct {
		name    string
		conf    string
		wantErr string
	}{
		{"missing private key",
			"[Interface]\nAddress = 10.0.0.2\n[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.1:51820\n",
			"private key"},
		{"bad base64 key",
			"[Interface]\nPrivateKey = not!!base64@@\nAddress = 10.0.0.2\n[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.1:51820\n",
			"private key"},
		{"short key",
			"[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 16)) + "\nAddress = 10.0.0.2\n[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.1:51820\n",
			"32 bytes"},
		{"missing address",
			"[Interface]\nPrivateKey = " + testPrivKey + "\n[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.1:51820\n",
			"address"},
		{"missing peer public key",
			"[Interface]\nPrivateKey = " + testPrivKey + "\nAddress = 10.0.0.2\n[Peer]\nEndpoint = 192.0.2.1:51820\n",
			"public key"},
		{"missing endpoint",
			"[Interface]\nPrivateKey = " + testPrivKey + "\nAddress = 10.0.0.2\n[Peer]\nPublicKey = " + testPubKey + "\n",
			"endpoint"},
		{"two peers",
			fullTestConfig() + "[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.9:1111\n",
			"multiple [Peer]"},
		{"unknown section",
			"[Bogus]\nFoo = bar\n",
			"unsupported section"},
		{"unknown interface field",
			"[Interface]\nPrivateKey = " + testPrivKey + "\nAddress = 10.0.0.2\nFrob = 1\n",
			"unsupported [Interface] field"},
		{"unknown peer field",
			"[Interface]\nPrivateKey = " + testPrivKey + "\nAddress = 10.0.0.2\n[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.1:51820\nNope = 1\n",
			"unsupported [Peer] field"},
		{"invalid address",
			"[Interface]\nPrivateKey = " + testPrivKey + "\nAddress = not-an-ip\n[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.1:51820\n",
			"invalid address"},
		{"invalid mtu",
			"[Interface]\nPrivateKey = " + testPrivKey + "\nAddress = 10.0.0.2\nMTU = huge\n[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.1:51820\n",
			"invalid MTU"},
		{"invalid keepalive",
			"[Interface]\nPrivateKey = " + testPrivKey + "\nAddress = 10.0.0.2\n[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.1:51820\nPersistentKeepalive = soon\n",
			"invalid persistent keepalive"},
		{"invalid endpoint port",
			"[Interface]\nPrivateKey = " + testPrivKey + "\nAddress = 10.0.0.2\n[Peer]\nPublicKey = " + testPubKey + "\nEndpoint = 192.0.2.1:none\n",
			"bad port"},
		{"empty value",
			"[Interface]\nPrivateKey =\n",
			"empty value"},
		{"no equals sign",
			"garbage line\n",
			"key=value"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWGConfig(strings.NewReader(tc.conf))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestLoadWGConfigMissingFile(t *testing.T) {
	if _, err := LoadWGConfig("does-not-exist.conf"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
