package main

import (
	"fmt"
	"net/netip"

	"github.com/aileron-projects/go-ipfilter"
)

func main() {
	wl := ipfilter.NewWhitelist()

	// Add in netip.Prefix
	wl.AllowPrefix(netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("192.168.1.1/16"))

	// Add in netip.Addr
	wl.AllowAddr(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.168.1.1"))

	// Add in string
	err := wl.Allow("127.0.0.1", "192.168.1.1/16")
	if err != nil {
		panic(err)
	}

	var target = []string{
		"127.0.0.1", "127.0.0.2",
		"192.168.1.1", "192.168.2.2",
		"10.0.0.1",
		"a,b,c,d",
	}
	for _, ip := range target {
		fmt.Printf("%s allowed? --- %t\n", ip, wl.Allowed(ip))
	}
}
