// dnscache.go implements a simple TTL-aware in-memory DNS cache for both the
// host resolver (net.LookupIP) and the tunnel resolver (tnet.LookupContextHost).
// It is safe for concurrent use.

package main

import (
	"net"
	"strings"
	"sync"
	"time"
)

// DNSCache is a thread-safe LRU-ish cache with TTL expiry. When maxSize is
// reached a random entry is evicted. A nil *DNSCache means caching is disabled.
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
	ttl     time.Duration
	maxSize int
}

type dnsCacheEntry struct {
	addrs  []string
	expiry time.Time
}

// NewDNSCache creates a cache. If ttl==0 or maxSize==0 it returns nil (disabled).
func NewDNSCache(ttl time.Duration, maxSize int) *DNSCache {
	if ttl <= 0 || maxSize <= 0 {
		return nil
	}
	return &DNSCache{
		entries: make(map[string]dnsCacheEntry, maxSize),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// normalizeHost lower-cases and trims a trailing dot.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

// Get returns cached addresses for host. The returned slice is a copy.
func (c *DNSCache) Get(host string) ([]string, bool) {
	if c == nil {
		return nil, false
	}
	host = normalizeHost(host)
	c.mu.RLock()
	e, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiry) {
		c.mu.Lock()
		// Re-check under write lock in case another goroutine refreshed it.
		if cur, ok := c.entries[host]; ok && cur.expiry.Equal(e.expiry) {
			delete(c.entries, host)
		}
		c.mu.Unlock()
		return nil, false
	}
	cp := make([]string, len(e.addrs))
	copy(cp, e.addrs)
	return cp, true
}

// Set stores addresses for host.
func (c *DNSCache) Set(host string, addrs []string) {
	if c == nil || len(addrs) == 0 {
		return
	}
	host = normalizeHost(host)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		// Evict one arbitrary entry (map iteration is random in Go).
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	cp := make([]string, len(addrs))
	copy(cp, addrs)
	c.entries[host] = dnsCacheEntry{addrs: cp, expiry: time.Now().Add(c.ttl)}
}

// GetIPs is a convenience wrapper for the host resolver that stores net.IP.
func (c *DNSCache) GetIPs(host string) ([]net.IP, bool) {
	strs, ok := c.Get(host)
	if !ok {
		return nil, false
	}
	ips := make([]net.IP, 0, len(strs))
	for _, s := range strs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, false
	}
	return ips, true
}

// SetIPs stores net.IP results.
func (c *DNSCache) SetIPs(host string, ips []net.IP) {
	if len(ips) == 0 {
		return
	}
	strs := make([]string, len(ips))
	for i, ip := range ips {
		strs[i] = ip.String()
	}
	c.Set(host, strs)
}

// Stats returns current size. Useful for debugging.
func (c *DNSCache) Stats() (size int) {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	size = len(c.entries)
	c.mu.RUnlock()
	return size
}

// Global caches. Initialized in main/run based on flags.
var (
	hostDNSCache   *DNSCache
	tunnelDNSCache *DNSCache
)
