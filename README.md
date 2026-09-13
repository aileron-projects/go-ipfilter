<!-- markdownlint-disable MD033 MD041 -->

<div align="center">

[![Release](https://img.shields.io/github/v/release/aileron-projects/go-ipfilter?sort=semver)](https://github.com/aileron-projects/go-ipfilter/releases)
[![Reference](https://pkg.go.dev/badge/github.com/aileron-projects/go-ipfilter.svg)](https://pkg.go.dev/github.com/aileron-projects/go-ipfilter)
[![DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/aileron-projects/go-ipfilter)
[![Test](https://github.com/aileron-projects/go-ipfilter/actions/workflows/test.yaml/badge.svg)](https://github.com/aileron-projects/go-ipfilter/actions/workflows/test.yaml)

[![Insights](https://badgen.net/badge/Insights/open%2Fsource%2Finsights/cyan)](https://deps.dev/go/github.com%2Faileron-projects%2Fgo-ipfilter)
[![Insights](https://badgen.net/badge/Insights/OSS%2FInsight/orange)](https://ossinsight.io/analyze/aileron-projects/go-ipfilter)

</div>

# go-ipfilter

**IP whitelist, blacklist and net.Listener wrappers for Go.**

## Features

- IP whitelist: `Whitelist`
- IP blacklist: `Blacklist`
- CIDR, or subnet, supported
- IPv4, IPv6 supported
- net.Listener wrappers (`WhitelistListener`, `BlacklistListener`)
- Fast (trie tree algorithm)
- Intuitive interface
- Zero dependency

## Usages

### IP whitelist

```go
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

fmt.Println(wl.Allowed("127.0.0.1"))   // true
fmt.Println(wl.Allowed("127.0.0.2"))   // false
fmt.Println(wl.Allowed("192.168.1.1")) // true
fmt.Println(wl.Allowed("192.168.2.2")) // true
fmt.Println(wl.Allowed("a.b.c.z"))     // false
```

### IP blacklist

```go
bl := ipfilter.NewBlacklist()

// Add in netip.Prefix
bl.DisallowPrefix(netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("192.168.1.1/16"))

// Add in netip.Addr
bl.DisallowAddr(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.168.1.1"))

// Add in string
err := bl.Disallow("127.0.0.1", "192.168.1.1/16")
if err != nil {
  panic(err)
}

fmt.Println(wl.Allowed("127.0.0.1"))   // false
fmt.Println(wl.Allowed("127.0.0.2"))   // true
fmt.Println(wl.Allowed("192.168.1.1")) // false
fmt.Println(wl.Allowed("192.168.2.2")) // false
fmt.Println(wl.Allowed("a.b.c.z"))     // false
```

### IP filter for listener

Use `ipfilter.WhitelistListener` or `ipfilter.BlacklistListener` to obtain a net lister with ip whitelist and blacklist.

The following example uses a whitelist.

```go
ln, err := net.Listen("tcp", ":8080")
if err != nil {
  panic(err)
}

// NG >>> curl --interface 127.0.0.1 http://localhost:8080
// OK >>> curl --interface 127.0.0.2 http://localhost:8080
// OK >>> curl --interface 127.0.0.3 http://localhost:8080
ln, err = ipfilter.WhitelistListener(ln, "127.0.0.2", "127.0.0.3")
if err != nil {
  panic(err)
}

svr := &http.Server{
  Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "Hello Gopher!!")
  }),
}

log.Println("server starting at ", ln.Addr().String())
if err := svr.Serve(ln); err != nil {
  panic(err)
}
```

## Docs & Examples

- GoDoc: <https://pkg.go.dev/github.com/aileron-projects/go-ipfilter>
- Examples:
  - [example_test.go](./example_test.go)
  - IP whitelist: [examples/whitelist/](./examples/whitelist/)
  - IP blacklist: [examples/blacklist/](./examples/blacklist/)
  - HTTP server or Listener with whitelist: [examples/whitelist-server/](./examples/whitelist-server/)
  - HTTP server or Listener with blacklist: [examples/blacklist-server/](./examples/blacklist-server/)

## Benchmarks

This benchmark shows the performance of worst case senarios.

See the [benchmark_test.go](./benchmark_test.go) for details.

```txt
goos: windows
goarch: amd64
cpu: 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz

BenchmarkWhitelist_ipv4-8   18551698    67.41 ns/op   0 B/op   0 allocs/op
BenchmarkBlacklist_ipv4-8   18852510    68.24 ns/op   0 B/op   0 allocs/op
BenchmarkWhitelist_ipv6-8    4235488   273.0  ns/op   0 B/op   0 allocs/op
BenchmarkBlacklist_ipv6-8    3790411   294.5  ns/op   0 B/op   0 allocs/op
```

## References

- <https://en.wikipedia.org/wiki/Trie>
