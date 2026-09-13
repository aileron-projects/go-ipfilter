package ipfilter

import (
	"net"
)

// WhitelistListener returns a new lister with IP whitelist.
// Connections are immediately closed when they were not allowed
// by the whitelist. Given ip addresses must be in valid form
// for [net/netip.ParsePrefix] or [net/netip.ParseAddr].
// ln must not be nil.
func WhitelistListener(ln net.Listener, allow ...string) (net.Listener, error) {
	wl := NewWhitelist()
	if err := wl.Allow(allow...); err != nil {
		return nil, err
	}
	return &allowListener{
		Listener: ln,
		allowed:  wl.Allowed,
	}, nil
}

// BlacklistListener returns a new lister with IP blacklist.
// Connections are immediately closed when they were not allowed
// by the blacklist. Given ip addresses must be in valid form
// for [net/netip.ParsePrefix] or [net/netip.ParseAddr].
// ln must not be nil.
func BlacklistListener(ln net.Listener, disallow ...string) (net.Listener, error) {
	bl := NewBlacklist()
	if err := bl.Disallow(disallow...); err != nil {
		return nil, err
	}
	return &allowListener{
		Listener: ln,
		allowed:  bl.Allowed,
	}, nil
}

// allowListener allows connections when the allowed function allowed.
type allowListener struct {
	net.Listener
	allowed func(host string) bool
}

func (l *allowListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}
	addr := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // Fallback
	}
	if !l.allowed(host) {
		_ = conn.Close() // Close immediately.
		return conn, nil
	}
	return conn, nil
}
