package ipfilter_test

import (
	"errors"
	"io"
	"net"
	"strconv"
	"testing"

	"github.com/aileron-projects/go-ipfilter"
	"github.com/aileron-projects/go-tester"
)

type testConn struct {
	net.Conn
	closed      bool
	closedCount int
	remote      net.Addr
}

func (c *testConn) Close() error {
	c.closed = true
	c.closedCount++
	return errors.New(strconv.Itoa(c.closedCount))
}

func (c *testConn) RemoteAddr() net.Addr {
	return c.remote
}

type testListener struct {
	net.Listener
	err    error
	remote net.Addr
	closed bool
}

func (l *testListener) Close() error {
	l.closed = true
	return nil
}

func (l *testListener) Accept() (net.Conn, error) {
	if l.closed {
		return nil, errors.New("closed")
	}
	return &testConn{remote: l.remote}, l.err
}

func TestWhitelistListener_new(t *testing.T) {
	t.Parallel()
	t.Run("ip", func(t *testing.T) {
		_, err := ipfilter.WhitelistListener(nil, "127.0.0.1")
		tester.AssertEqual(t, true, err == nil)
	})
	t.Run("prefix", func(t *testing.T) {
		_, err := ipfilter.WhitelistListener(nil, "127.0.0.1/32")
		tester.AssertEqual(t, true, err == nil)
	})
	t.Run("error ip", func(t *testing.T) {
		_, err := ipfilter.WhitelistListener(nil, "127.0.0.?")
		tester.AssertEqual(t, true, err != nil)
	})
	t.Run("error prefix", func(t *testing.T) {
		_, err := ipfilter.WhitelistListener(nil, "127.0.0.?/8")
		tester.AssertEqual(t, true, err != nil)
	})
}

func TestBlacklistListener_new(t *testing.T) {
	t.Parallel()
	t.Run("ip", func(t *testing.T) {
		_, err := ipfilter.BlacklistListener(nil, "127.0.0.1")
		tester.AssertEqual(t, true, err == nil)
	})
	t.Run("prefix", func(t *testing.T) {
		_, err := ipfilter.BlacklistListener(nil, "127.0.0.1/32")
		tester.AssertEqual(t, true, err == nil)
	})
	t.Run("error ip", func(t *testing.T) {
		_, err := ipfilter.BlacklistListener(nil, "127.0.0.?")
		tester.AssertEqual(t, true, err != nil)
	})
	t.Run("error prefix", func(t *testing.T) {
		_, err := ipfilter.BlacklistListener(nil, "127.0.0.?/8")
		tester.AssertEqual(t, true, err != nil)
	})
}

func TestWhitelistListener(t *testing.T) {
	t.Parallel()
	dummyListener := func(ip string, port int) *testListener {
		return &testListener{remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: port}}
	}
	testCases := []struct {
		ln     net.Listener
		closed bool  // want
		err    error // want
	}{
		{ln: dummyListener("127.0.0.1", 80), closed: false},
		{ln: dummyListener("127.0.0.255", 80), closed: false},
		{ln: dummyListener("127.0.1.0", 80), closed: true},
		{ln: dummyListener("192.168.255.255", 80), closed: false},
		{ln: dummyListener("192.169.0.0", 80), closed: true},
		{ln: &testListener{err: io.EOF}, err: io.EOF},
		{
			ln:     &testListener{remote: &net.UnixAddr{Name: "@example"}},
			closed: true,
		},
	}
	for i, tc := range testCases {
		t.Run("case:"+strconv.Itoa(i), func(t *testing.T) {
			ln, _ := ipfilter.WhitelistListener(tc.ln, "127.0.0.0/24", "192.168.0.0/16")
			conn, err := ln.Accept()
			tester.AssertEqualErr(t, tc.err, err)
			tester.AssertEqual(t, tc.closed, conn.(*testConn).closed)
		})
	}
}

func TestBlacklistListener(t *testing.T) {
	t.Parallel()
	dummyListener := func(ip string, port int) *testListener {
		return &testListener{remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: port}}
	}
	testCases := []struct {
		ln     net.Listener
		closed bool  // want
		err    error // want
	}{
		{ln: dummyListener("127.0.0.1", 80), closed: true},
		{ln: dummyListener("127.0.0.255", 80), closed: true},
		{ln: dummyListener("127.0.1.0", 80), closed: false},
		{ln: dummyListener("192.168.255.255", 80), closed: true},
		{ln: dummyListener("192.169.0.0", 80), closed: false},
		{ln: &testListener{err: io.EOF}, err: io.EOF},
		{
			ln:     &testListener{remote: &net.UnixAddr{Name: "@example"}},
			closed: true,
		},
	}
	for i, tc := range testCases {
		t.Run("case:"+strconv.Itoa(i), func(t *testing.T) {
			ln, _ := ipfilter.BlacklistListener(tc.ln, "127.0.0.0/24", "192.168.0.0/16")
			conn, err := ln.Accept()
			tester.AssertEqualErr(t, tc.err, err)
			tester.AssertEqual(t, tc.closed, conn.(*testConn).closed)
		})
	}
}
