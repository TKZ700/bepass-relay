package main

import (
	"net"
	"testing"
	"time"
)

func TestDNSCacheHitAndMiss(t *testing.T) {
	c := NewDNSCache(time.Minute, 10)
	if _, ok := c.Get("example.com"); ok {
		t.Fatal("expected miss on empty cache")
	}
	c.Set("example.com", []string{"1.2.3.4"})
	addrs, ok := c.Get("example.com")
	if !ok || len(addrs) != 1 || addrs[0] != "1.2.3.4" {
		t.Fatalf("expected hit, got %v %v", addrs, ok)
	}
}

func TestDNSCacheCaseInsensitive(t *testing.T) {
	c := NewDNSCache(time.Minute, 10)
	c.Set("Example.COM", []string{"1.2.3.4"})
	if _, ok := c.Get("example.com"); !ok {
		t.Fatal("expected case-insensitive hit")
	}
	if _, ok := c.Get("EXAMPLE.COM"); !ok {
		t.Fatal("expected case-insensitive hit")
	}
}

func TestDNSCacheExpiry(t *testing.T) {
	c := NewDNSCache(10*time.Millisecond, 10)
	c.Set("example.com", []string{"1.2.3.4"})
	time.Sleep(20 * time.Millisecond)
	if _, ok := c.Get("example.com"); ok {
		t.Fatal("expected expired entry to miss")
	}
}

func TestDNSCacheMaxSizeEviction(t *testing.T) {
	c := NewDNSCache(time.Minute, 2)
	c.Set("a.com", []string{"1.1.1.1"})
	c.Set("b.com", []string{"2.2.2.2"})
	c.Set("c.com", []string{"3.3.3.3"})
	if c.Stats() != 2 {
		t.Fatalf("expected size 2, got %d", c.Stats())
	}
}

func TestDNSCacheIPs(t *testing.T) {
	c := NewDNSCache(time.Minute, 10)
	ips := []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("2001:db8::1")}
	c.SetIPs("example.com", ips)
	got, ok := c.GetIPs("example.com")
	if !ok || len(got) != 2 {
		t.Fatalf("expected 2 IPs, got %v %v", got, ok)
	}
}

func TestDNSCacheDisabled(t *testing.T) {
	var c *DNSCache = NewDNSCache(0, 10)
	if c != nil {
		t.Fatal("expected nil for 0 TTL")
	}
	c = NewDNSCache(time.Minute, 0)
	if c != nil {
		t.Fatal("expected nil for 0 size")
	}
	// nil cache should not panic on Get/Set
	if _, ok := c.Get("example.com"); ok {
		t.Fatal("nil cache should miss")
	}
	c.Set("example.com", []string{"1.2.3.4"})
}
