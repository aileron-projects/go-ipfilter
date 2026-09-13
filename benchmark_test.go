package ipfilter

import (
	"crypto/rand"
	"net/netip"
	"testing"
)

func BenchmarkWhitelist_ipv4(b *testing.B) {
	wl := NewWhitelist()
	wl.AllowPrefix(randomIPv4(10000)...)
	wl.AllowPrefix(randomIPv6(10000)...)
	wl.Allow("255.255.255.255/32")
	b.ResetTimer()
	for b.Loop() {
		_ = wl.Allowed("255.255.255.255") // Always allowed
	}
}

func BenchmarkBlacklist_ipv4(b *testing.B) {
	wl := NewBlacklist()
	wl.DisallowPrefix(randomIPv4(10000)...)
	wl.DisallowPrefix(randomIPv6(10000)...)
	wl.Disallow("255.255.255.255/32")
	b.ResetTimer()
	for b.Loop() {
		_ = wl.Allowed("255.255.255.255") // Always disallowed
	}
}

func BenchmarkWhitelist_ipv6(b *testing.B) {
	wl := NewWhitelist()
	wl.AllowPrefix(randomIPv4(10000)...)
	wl.AllowPrefix(randomIPv6(10000)...)
	wl.Allow("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")
	b.ResetTimer()
	for b.Loop() {
		_ = wl.Allowed("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") // Always allowed
	}
}

func BenchmarkBlacklist_ipv6(b *testing.B) {
	wl := NewBlacklist()
	wl.DisallowPrefix(randomIPv4(10000)...)
	wl.DisallowPrefix(randomIPv6(10000)...)
	wl.Disallow("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")
	b.ResetTimer()
	for b.Loop() {
		_ = wl.Allowed("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") // Always disallowed
	}
}

func randomIPv4(n int) []netip.Prefix {
	addrs := make([]netip.Prefix, n)
	for i := range n {
		var b [4]byte
		rand.Read(b[:])
		ip := netip.AddrFrom4(b)
		bits := 32 // 28+mrand.IntN(5)
		prefix := netip.PrefixFrom(ip, bits)
		addrs[i] = prefix
	}
	return addrs
}

func randomIPv6(n int) []netip.Prefix {
	addrs := make([]netip.Prefix, n)
	for i := range n {
		var b [16]byte
		rand.Read(b[:])
		ip := netip.AddrFrom16(b)
		bits := 128 // 120+mrand.IntN(9)
		prefix := netip.PrefixFrom(ip, bits)
		addrs[i] = prefix
	}
	return addrs
}
