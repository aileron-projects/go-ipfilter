package ipfilter

import (
	"fmt"
)

func ExampleWhitelist_ipv4Only() {
	wl := NewWhitelist()
	err := wl.Allow("0.0.0.0/0")
	if err != nil {
		panic(err)
	}

	targetIPs := []string{
		"127.0.0.1", "192.168.1.1", "126.0.0.1", "192.169.1.1",
		"fd00:0:0::1", "fd00:0:0:1::1", "fd00:0:1::1", "fc00:0:0::1",
	}
	for _, ip := range targetIPs {
		fmt.Printf("%s --> %v\n", ip, wl.Allowed(ip))
	}
	// Output:
	// 127.0.0.1 --> true
	// 192.168.1.1 --> true
	// 126.0.0.1 --> true
	// 192.169.1.1 --> true
	// fd00:0:0::1 --> false
	// fd00:0:0:1::1 --> false
	// fd00:0:1::1 --> false
	// fc00:0:0::1 --> false
}
func ExampleWhitelist_ipv6Only() {
	wl := NewWhitelist()
	err := wl.Allow("::/0")
	if err != nil {
		panic(err)
	}

	targetIPs := []string{
		"127.0.0.1", "192.168.1.1", "126.0.0.1", "192.169.1.1",
		"fd00:0:0::1", "fd00:0:0:1::1", "fd00:0:1::1", "fc00:0:0::1",
	}
	for _, ip := range targetIPs {
		fmt.Printf("%s --> %v\n", ip, wl.Allowed(ip))
	}
	// Output:
	// 127.0.0.1 --> false
	// 192.168.1.1 --> false
	// 126.0.0.1 --> false
	// 192.169.1.1 --> false
	// fd00:0:0::1 --> true
	// fd00:0:0:1::1 --> true
	// fd00:0:1::1 --> true
	// fc00:0:0::1 --> true
}

func ExampleWhitelist() {
	wl := NewWhitelist()
	err := wl.Allow("127.0.0.0/8", "192.168.0.0/16", "fd00:0:0::/48")
	if err != nil {
		panic(err)
	}

	targetIPs := []string{
		"127.0.0.1",     // OK
		"192.168.1.1",   // OK
		"126.0.0.1",     // NG
		"192.169.1.1",   // NG
		"fd00:0:0::1",   // OK
		"fd00:0:0:1::1", // OK
		"fd00:0:1::1",   // NG
		"fc00:0:0::1",   // NG

	}
	for _, ip := range targetIPs {
		fmt.Printf("%s --> %v\n", ip, wl.Allowed(ip))
	}
	// Output:
	// 127.0.0.1 --> true
	// 192.168.1.1 --> true
	// 126.0.0.1 --> false
	// 192.169.1.1 --> false
	// fd00:0:0::1 --> true
	// fd00:0:0:1::1 --> true
	// fd00:0:1::1 --> false
	// fc00:0:0::1 --> false
}

func ExampleWhitelist_ipv4() {
	prefixes := []string{
		"10.0.0.0/8",     // 10.0.0.0–10.255.255.255 Private network
		"100.64.0.0/10",  // 100.64.0.0–100.127.255.255 Private network
		"127.0.0.0/8",    // 127.0.0.0–127.255.255.255 Host
		"172.16.0.0/12",  // 172.16.0.0–172.31.255.255 Private network
		"192.0.0.0/24",   // 192.0.0.0–192.0.0.255 Private network
		"192.168.0.0/16", // 192.168.0.0–192.168.255.255 Private network
		"198.18.0.0/15",  // 198.18.0.0–198.19.255.255 Private network
	}

	wl := NewWhitelist()
	err := wl.Allow(prefixes...)
	if err != nil {
		panic(err)
	}

	targetIPs := []string{
		"10.255.255.1",  // OK
		"127.0.0.1",     // OK
		"192.168.1.2",   // OK
		"192.88.10.20",  // NG
		"224.10.20.30",  // NG
		"255.255.10.20", // NG
	}
	for _, ip := range targetIPs {
		fmt.Printf("%s --> %v\n", ip, wl.Allowed(ip))
	}
	// Output:
	// 10.255.255.1 --> true
	// 127.0.0.1 --> true
	// 192.168.1.2 --> true
	// 192.88.10.20 --> false
	// 224.10.20.30 --> false
	// 255.255.10.20 --> false
}

func ExampleBlacklist_ipv4() {
	prefixes := []string{
		"10.0.0.0/8",     // 10.0.0.0–10.255.255.255 Private network
		"100.64.0.0/10",  // 100.64.0.0–100.127.255.255 Private network
		"127.0.0.0/8",    // 127.0.0.0–127.255.255.255 Host
		"172.16.0.0/12",  // 172.16.0.0–172.31.255.255 Private network
		"192.0.0.0/24",   // 192.0.0.0–192.0.0.255 Private network
		"192.168.0.0/16", // 192.168.0.0–192.168.255.255 Private network
		"198.18.0.0/15",  // 198.18.0.0–198.19.255.255 Private network
	}

	bl := NewBlacklist()
	err := bl.Disallow(prefixes...)
	if err != nil {
		panic(err)
	}

	targetIPs := []string{
		"10.255.255.1",  // NG
		"127.0.0.1",     // NG
		"192.168.1.2",   // NG
		"192.88.10.20",  // OK
		"224.10.20.30",  // OK
		"255.255.10.20", // OK
	}
	for _, ip := range targetIPs {
		fmt.Printf("%s --> %v\n", ip, bl.Allowed(ip))
	}
	// Output:
	// 10.255.255.1 --> false
	// 127.0.0.1 --> false
	// 192.168.1.2 --> false
	// 192.88.10.20 --> true
	// 224.10.20.30 --> true
	// 255.255.10.20 --> true
}
