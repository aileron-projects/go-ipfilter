package ipfilter_test

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/aileron-projects/go-ipfilter"
	"github.com/aileron-projects/go-tester"
)

const (
	v4Zero = "0.0.0.0"
	v4Max  = "255.255.255.255"
	v6Zero = "::0"
	v6Max  = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
)

func TestWhitelist_Allowed(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		allow      []string
		allowed    []string
		disallowed []string
	}{
		{[]string{}, []string{}, []string{v4Zero, v4Max, v6Zero, v6Max}},
		{[]string{"127.0.0.1"}, []string{"127.0.0.1"}, []string{"127.0.0.2"}},
		{[]string{"127.0.0.1/32"}, []string{"127.0.0.1"}, []string{"127.0.0.2"}},
		{[]string{"::1"}, []string{"::1"}, []string{"::2"}},
		{[]string{"::1/128"}, []string{"::1"}, []string{"::2"}},
		{
			[]string{"127.0.0.0/8", "128.0.0.0/8"},
			[]string{"127.255.255.255", "128.255.255.255"},
			[]string{v4Zero, v4Max, v6Zero, v6Max, "129.0.0.0"},
		},
		{
			[]string{"127.0.0.0/8", "127.1.0.0/16"},
			[]string{"127.255.255.255"},
			[]string{v4Zero, v4Max, v6Zero, v6Max, "129.0.0.0"},
		},
		{
			[]string{"fffe::/16", "ffff::/16"},
			[]string{"fffe:ffff::", "ffff:ffff::"},
			[]string{v4Zero, v4Max, v6Zero},
		},
	}
	for i, tc := range testCases {
		t.Run("case:"+strconv.Itoa(i), func(t *testing.T) {
			l := ipfilter.NewWhitelist()
			err := l.Allow(tc.allow...)
			tester.AssertEqual(t, nil, err)
			tester.AssertEqual(t, false, l.Allowed("invalid"))
			for _, ip := range tc.allowed {
				allowed := l.Allowed(ip)
				t.Log(ip, allowed)
				tester.AssertEqual(t, true, allowed)
			}
			for _, ip := range tc.disallowed {
				allowed := l.Allowed(ip)
				t.Log(ip, allowed)
				tester.AssertEqual(t, false, allowed)
			}
		})
	}
}

func TestWhitelist_AllowPrefix(t *testing.T) {
	t.Parallel()
	wl := ipfilter.NewWhitelist()
	wl.AllowPrefix(
		netip.Prefix{}, // invalid
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("192.0.0.0/8"),
	)
	allowed := []string{"127.0.0.1", "192.255.255.255"}
	disallowed := []string{"127.0.0.2", "193.0.0.0"}
	for _, ip := range allowed {
		t.Log(ip)
		tester.AssertEqual(t, true, wl.Allowed(ip))
	}
	for _, ip := range disallowed {
		t.Log(ip)
		tester.AssertEqual(t, false, wl.Allowed(ip))
	}
}

func TestWhitelist_AllowAddr(t *testing.T) {
	t.Parallel()
	wl := ipfilter.NewWhitelist()
	wl.AllowAddr(
		netip.Addr{}, // invalid
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("192.0.0.0"),
	)
	allowed := []string{"127.0.0.1", "192.0.0.0"}
	disallowed := []string{"127.0.0.2", "192.0.0.1"}
	for _, ip := range allowed {
		t.Log(ip)
		tester.AssertEqual(t, true, wl.Allowed(ip))
	}
	for _, ip := range disallowed {
		t.Log(ip)
		tester.AssertEqual(t, false, wl.Allowed(ip))
	}
}

func TestWhitelist_AllowedAddr(t *testing.T) {
	t.Parallel()
	bl := ipfilter.NewWhitelist()
	bl.AllowAddr(netip.MustParseAddr("127.0.0.1"))
	tester.AssertEqual(t, true, bl.AllowedAddr(netip.MustParseAddr("127.0.0.1")))
	tester.AssertEqual(t, false, bl.AllowedAddr(netip.MustParseAddr("127.0.0.2")))
	tester.AssertEqual(t, false, bl.AllowedAddr(netip.Addr{}))
}

func TestBlacklist_Allowed(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		allow      []string
		disallowed []string
		allowed    []string
	}{
		{[]string{}, []string{}, []string{v4Zero, v4Max, v6Zero, v6Max}},
		{[]string{"127.0.0.1"}, []string{"127.0.0.1"}, []string{"127.0.0.2"}},
		{[]string{"127.0.0.1/32"}, []string{"127.0.0.1"}, []string{"127.0.0.2"}},
		{[]string{"::1"}, []string{"::1"}, []string{"::2"}},
		{[]string{"::1/128"}, []string{"::1"}, []string{"::2"}},
		{
			[]string{"127.0.0.0/8", "128.0.0.0/8"},
			[]string{"127.255.255.255", "128.255.255.255"},
			[]string{v4Zero, v4Max, v6Zero, v6Max, "129.0.0.0"},
		},
		{
			[]string{"127.0.0.0/8", "127.1.0.0/16"},
			[]string{"127.255.255.255"},
			[]string{v4Zero, v4Max, v6Zero, v6Max, "129.0.0.0"},
		},
		{
			[]string{"fffe::/16", "ffff::/16"},
			[]string{"fffe:ffff::", "ffff:ffff::"},
			[]string{v4Zero, v4Max, v6Zero},
		},
	}
	for i, tc := range testCases {
		t.Run("case:"+strconv.Itoa(i), func(t *testing.T) {
			l := ipfilter.NewBlacklist()
			err := l.Disallow(tc.disallowed...)
			tester.AssertEqual(t, nil, err)
			tester.AssertEqual(t, false, l.Allowed("invalid"))
			for _, ip := range tc.allowed {
				allowed := l.Allowed(ip)
				t.Log(ip, allowed)
				tester.AssertEqual(t, true, allowed)
			}
			for _, ip := range tc.disallowed {
				allowed := l.Allowed(ip)
				t.Log(ip, allowed)
				tester.AssertEqual(t, false, allowed)
			}
		})
	}
}

func TestBlacklist_DisallowPrefix(t *testing.T) {
	t.Parallel()
	bl := ipfilter.NewBlacklist()
	bl.DisallowPrefix(
		netip.Prefix{}, // invalid
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("192.0.0.0/8"),
	)
	disallowed := []string{"127.0.0.1", "192.255.255.255"}
	allowed := []string{"127.0.0.2", "193.0.0.0"}
	for _, ip := range allowed {
		t.Log(ip)
		tester.AssertEqual(t, true, bl.Allowed(ip))
	}
	for _, ip := range disallowed {
		t.Log(ip)
		tester.AssertEqual(t, false, bl.Allowed(ip))
	}
}

func TestBlacklist_DisallowAddr(t *testing.T) {
	t.Parallel()
	bl := ipfilter.NewBlacklist()
	bl.DisallowAddr(
		netip.Addr{}, // invalid
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("192.0.0.0"),
	)

	disallowed := []string{"127.0.0.1", "192.0.0.0"}
	allowed := []string{"127.0.0.2", "192.0.0.1"}
	for _, ip := range allowed {
		t.Log(ip)
		tester.AssertEqual(t, true, bl.Allowed(ip))
	}
	for _, ip := range disallowed {
		t.Log(ip)
		tester.AssertEqual(t, false, bl.Allowed(ip))
	}
}

func TestBlacklist_AllowedAddr(t *testing.T) {
	t.Parallel()
	bl := ipfilter.NewBlacklist()
	bl.DisallowAddr(netip.MustParseAddr("127.0.0.1"))
	tester.AssertEqual(t, false, bl.AllowedAddr(netip.MustParseAddr("127.0.0.1")))
	tester.AssertEqual(t, true, bl.AllowedAddr(netip.MustParseAddr("127.0.0.2")))
	tester.AssertEqual(t, false, bl.AllowedAddr(netip.Addr{}))
}
