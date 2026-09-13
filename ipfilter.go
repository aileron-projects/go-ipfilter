package ipfilter

import (
	"net/netip"
	"strings"
)

// addrList is the IPv4 and IPv6 address list.
type addrList struct {
	ipV4 *rootNode
	ipV6 *rootNode
}

// add adds addresses to the list.
// When an address contains "/" it will be parsed with [net/netip.ParsePrefix],
// others will be parsed with [net/netip.ParseAddr].
// Given addresses must be in valid form for the functions.
// If parsing an address encounters an error, add immediately returns
// the error without processing the remaining addresses.
// When using CIDR, "/0" matches to all IPs and "<IPv4>/32" or "<IPv6>/128"
// matches to the only specified IP.
func (l *addrList) add(addrs ...string) error {
	for _, addr := range addrs {
		if strings.Contains(addr, "/") {
			pf, err := netip.ParsePrefix(addr)
			if err != nil {
				return err
			}
			l.addPrefix(pf)
		} else {
			ad, err := netip.ParseAddr(addr)
			if err != nil {
				return err
			}
			l.addAddr(ad)
		}
	}
	return nil
}

// addPrefix adds ipv4 and ipv6 addresses.
// Invalid, non-ipv4 nor non-ipv6, addresses are ignored.
func (l *addrList) addPrefix(pfs ...netip.Prefix) {
	for _, pf := range pfs {
		addr := pf.Addr()
		switch {
		case addr.Is4():
			v4 := addr.As4()
			l.ipV4.add(pf.Bits(), v4[:])
		case addr.Is6():
			v6 := addr.As16()
			l.ipV6.add(pf.Bits(), v6[:])
		default:
			continue // ignore invalids
		}
	}
}

// addAddr adds ipv4 and ipv6 addresses.
// Invalid, non-ipv4 nor non-ipv6, addresses are ignored.
func (l *addrList) addAddr(addrs ...netip.Addr) {
	for _, addr := range addrs {
		switch {
		case addr.Is4():
			v4 := addr.As4()
			l.ipV4.add(32, v4[:])
		case addr.Is6():
			v6 := addr.As16()
			l.ipV6.add(128, v6[:])
		default:
			continue // ignore invalids
		}
	}
}

// NewWhitelist returns a new instance of [Whitelist].
// [Whitelist] checks IPv4 and IPv6 addresses with whitelist.
func NewWhitelist() *Whitelist {
	return &Whitelist{
		whitelist: &addrList{
			ipV4: &rootNode{},
			ipV6: &rootNode{},
		},
	}
}

// Whitelist is the IP whitelist.
type Whitelist struct {
	whitelist *addrList
}

// Allow adds addresses to the whitelist.
// When an address contains "/" it will be parsed with [net/netip.ParsePrefix],
// others will be parsed with [net/netip.ParseAddr].
// Given addresses must be in valid form for the functions.
// If parsing an address encounters an error, add immediately returns
// the error without processing the remaining addresses.
// When using CIDR, "/0" matches to all IPs and "<IPv4>/32" or "<IPv6>/128"
// matches to the only specified IP.
func (wl *Whitelist) Allow(addrs ...string) error {
	return wl.whitelist.add(addrs...)
}

// AllowPrefix adds ipv4 and ipv6 addresses to the whitelist.
// Invalid, non-ipv4 nor non-ipv6, addresses are ignored.
func (wl *Whitelist) AllowPrefix(addrs ...netip.Prefix) {
	wl.whitelist.addPrefix(addrs...)
}

// AllowAddr adds ipv4 and ipv6 addresses to the whitelist.
// Invalid, non-ipv4 nor non-ipv6, addresses are ignored.
func (wl *Whitelist) AllowAddr(addrs ...netip.Addr) {
	wl.whitelist.addAddr(addrs...)
}

// Allowed returns if the addr is allowed by the whitelist.
// Both IPv4 and IPv6 are accepted.
func (wl *Whitelist) Allowed(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return wl.AllowedAddr(addr)
}

// AllowedAddr returns if the addr is allowed by the whitelist.
// Both IPv4 and IPv6 are accepted.
func (wl *Whitelist) AllowedAddr(addr netip.Addr) bool {
	switch {
	case addr.Is4():
		v4 := addr.As4()
		return wl.whitelist.ipV4.contains(v4[:])
	case addr.Is6():
		v6 := addr.As16()
		return wl.whitelist.ipV6.contains(v6[:])
	}
	return false
}

// NewBlacklist returns a new instance of [Blacklist].
// [Blacklist] checks IPv4 and IPv6 addresses with blacklist.
func NewBlacklist() *Blacklist {
	return &Blacklist{
		blacklist: &addrList{
			ipV4: &rootNode{},
			ipV6: &rootNode{},
		},
	}
}

// Blacklist is the IP blacklist.
type Blacklist struct {
	blacklist *addrList
}

// Disallow adds addresses to the blacklist.
// When an address contains "/" it will be parsed with [net/netip.ParsePrefix],
// others will be parsed with [net/netip.ParseAddr].
// Given addresses must be in valid form for the functions.
// If parsing an address encounters an error, add immediately returns
// the error without processing the remaining addresses.
// When using CIDR, "/0" matches to all IPs and "<IPv4>/32" or "<IPv6>/128"
// matches to the only specified IP.
func (bl *Blacklist) Disallow(addrs ...string) error {
	return bl.blacklist.add(addrs...)
}

// DisallowPrefix adds ipv4 and ipv6 addresses to the blacklist.
// Invalid, non-ipv4 nor non-ipv6, addresses are ignored.
func (bl *Blacklist) DisallowPrefix(addrs ...netip.Prefix) {
	bl.blacklist.addPrefix(addrs...)
}

// DisallowAddr adds ipv4 and ipv6 addresses to the blacklist.
// Invalid, non-ipv4 nor non-ipv6, addresses are ignored.
func (bl *Blacklist) DisallowAddr(addrs ...netip.Addr) {
	bl.blacklist.addAddr(addrs...)
}

// Allowed returns if the ip is allowed by the blacklist.
// Both IPv4 and IPv6 are accepted.
func (bl *Blacklist) Allowed(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return bl.AllowedAddr(addr)
}

// AllowedAddr returns if the addr is allowed by the blacklist.
// Both IPv4 and IPv6 are accepted.
func (bl *Blacklist) AllowedAddr(addr netip.Addr) bool {
	switch {
	case addr.Is4():
		v4 := addr.As4()
		return !bl.blacklist.ipV4.contains(v4[:])
	case addr.Is6():
		v6 := addr.As16()
		return !bl.blacklist.ipV6.contains(v6[:])
	}
	return false
}
