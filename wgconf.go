// wgconf.go implements a parser for wg-quick style WireGuard configuration files.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const wgDefaultMTU = 1280

// wgPeerConfig holds the parsed [Peer] section of a WireGuard config file.
type wgPeerConfig struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	PersistentKeepalive int
}

// wgConfig holds the parsed WireGuard configuration used to build the tunnel.
type wgConfig struct {
	PrivateKey string
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	ListenPort int
	Peer       wgPeerConfig
}

// LoadWGConfig reads and parses a wg-quick style config file from disk.
func LoadWGConfig(path string) (*wgConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return ParseWGConfig(f)
}

// ParseWGConfig parses a wg-quick style WireGuard configuration from r.
func ParseWGConfig(r io.Reader) (*wgConfig, error) {
	cfg := &wgConfig{MTU: wgDefaultMTU}
	inPeer := false
	seenPeer := false

	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")) {
			case "interface":
				inPeer = false
			case "peer":
				if seenPeer {
					return nil, fmt.Errorf("line %d: multiple [Peer] sections are not supported", lineNo)
				}
				seenPeer = true
				inPeer = true
			default:
				return nil, fmt.Errorf("line %d: unsupported section %q", lineNo, line)
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key=value pair", lineNo)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("line %d: empty value for %q", lineNo, key)
		}

		var err error
		if inPeer {
			err = applyPeerField(&cfg.Peer, key, value)
		} else {
			err = applyInterfaceField(cfg, key, value)
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyInterfaceField(cfg *wgConfig, key, value string) error {
	switch key {
	case "privatekey":
		cfg.PrivateKey = value
	case "address":
		prefixes, err := parsePrefixList(value)
		if err != nil {
			return err
		}
		cfg.Addresses = append(cfg.Addresses, prefixes...)
	case "dns":
		addrs, err := parseAddrList(value)
		if err != nil {
			return err
		}
		cfg.DNS = append(cfg.DNS, addrs...)
	case "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil || mtu <= 0 || mtu > 65535 {
			return fmt.Errorf("invalid MTU %q", value)
		}
		cfg.MTU = mtu
	case "listenport":
		port, err := strconv.Atoi(value)
		if err != nil || port < 0 || port > 65535 {
			return fmt.Errorf("invalid listen port %q", value)
		}
		cfg.ListenPort = port
	default:
		return fmt.Errorf("unsupported [Interface] field %q", key)
	}
	return nil
}

func applyPeerField(peer *wgPeerConfig, key, value string) error {
	switch key {
	case "publickey":
		peer.PublicKey = value
	case "presharedkey":
		peer.PresharedKey = value
	case "endpoint":
		if err := validateEndpoint(value); err != nil {
			return err
		}
		peer.Endpoint = value
	case "persistentkeepalive":
		ka, err := strconv.Atoi(value)
		if err != nil || ka < 0 || ka > 65535 {
			return fmt.Errorf("invalid persistent keepalive %q", value)
		}
		peer.PersistentKeepalive = ka
	case "allowedips":
		// The relay forces routing to 0.0.0.0/0 and ::/0, so allowed IPs
		// from the file are accepted but ignored.
	default:
		return fmt.Errorf("unsupported [Peer] field %q", key)
	}
	return nil
}

func (c *wgConfig) validate() error {
	if _, err := parseWGKey(c.PrivateKey); err != nil {
		return fmt.Errorf("invalid interface private key: %w", err)
	}
	if len(c.Addresses) == 0 {
		return fmt.Errorf("interface address is required")
	}
	if _, err := parseWGKey(c.Peer.PublicKey); err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}
	if c.Peer.Endpoint == "" {
		return fmt.Errorf("peer endpoint is required")
	}
	if c.Peer.PresharedKey != "" {
		if _, err := parseWGKey(c.Peer.PresharedKey); err != nil {
			return fmt.Errorf("invalid preshared key: %w", err)
		}
	}
	return nil
}

func validateEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	if host == "" {
		return fmt.Errorf("invalid endpoint %q: missing host", endpoint)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return fmt.Errorf("invalid endpoint %q: bad port", endpoint)
	}
	return nil
}

func parsePrefixList(list string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			prefixes = append(prefixes, p)
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", part)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

func parseAddrList(list string) ([]netip.Addr, error) {
	var addrs []netip.Addr
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS address %q", part)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// parseWGKey decodes a base64 encoded 32 byte WireGuard key.
func parseWGKey(key string) ([32]byte, error) {
	var raw [32]byte
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return raw, err
	}
	if len(b) != 32 {
		return raw, fmt.Errorf("key must decode to 32 bytes, got %d", len(b))
	}
	copy(raw[:], b)
	return raw, nil
}

func wgKeyHex(key string) (string, error) {
	raw, err := parseWGKey(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// buildIPCConfig renders the configuration in the UAPI IPC format consumed by
// device.IpcSet. The endpoint must already be resolved to an ip:port string.
func buildIPCConfig(c *wgConfig, endpoint string) (string, error) {
	privHex, err := wgKeyHex(c.PrivateKey)
	if err != nil {
		return "", err
	}
	pubHex, err := wgKeyHex(c.Peer.PublicKey)
	if err != nil {
		return "", err
	}

	keepalive := c.Peer.PersistentKeepalive
	if keepalive == 0 {
		keepalive = 25
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	if c.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	}
	fmt.Fprintf(&b, "public_key=%s\n", pubHex)
	if c.Peer.PresharedKey != "" {
		pskHex, err := wgKeyHex(c.Peer.PresharedKey)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", pskHex)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "allowed_ip=::/0\n")
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	return b.String(), nil
}
