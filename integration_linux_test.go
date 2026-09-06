//go:build linux

package kquic_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/kquic"
	"github.com/mdlayher/kquic/internal/quicsys"
	"golang.org/x/sys/unix"
)

// alpn is the ALPN protocol used by the loopback tests. It is arbitrary, but
// must match on both sides because the kernel demultiplexes on it.
const alpn = "kquic-test"

func TestIntegrationLoopbackStreams(t *testing.T) {
	probe(t)

	cert := selfSignedCert(t)

	l, err := kquic.Listen(netip.MustParseAddrPort("127.0.0.1:0"), &kquic.Config{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{alpn},
		},
	})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	if addr := l.Addr(); !addr.Addr().IsLoopback() || addr.Port() == 0 {
		t.Fatalf("unexpected listener address: %s", addr)
	}

	client, server := dialAccept(t, l, cert)
	defer client.Close()
	defer server.Close()

	// Nothing below should block for long; use deadlines so that a
	// misbehaving kernel fails the test rather than hanging it.
	deadline := time.Now().Add(10 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatalf("failed to set client deadline: %v", err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatalf("failed to set server deadline: %v", err)
	}

	// Both sides completed a TLS 1.3 handshake with the expected ALPN.
	for _, c := range []*kquic.Conn{client, server} {
		cs := c.ConnectionState()
		if !cs.HandshakeComplete {
			t.Fatalf("%s: handshake not complete", c.LocalAddr())
		}
		if want, got := uint16(tls.VersionTLS13), cs.Version; want != got {
			t.Fatalf("%s: unexpected TLS version: want %s, got %s",
				c.LocalAddr(), tls.VersionName(want), tls.VersionName(got))
		}
		if want, got := alpn, cs.NegotiatedProtocol; want != got {
			t.Fatalf("%s: unexpected ALPN protocol: want %q, got %q", c.LocalAddr(), want, got)
		}
	}

	// The client verified the server's self-signed certificate against the
	// pinned root, and the addresses line up.
	if cs := client.ConnectionState(); len(cs.VerifiedChains) == 0 ||
		!bytes.Equal(cs.PeerCertificates[0].Raw, cert.Certificate[0]) {
		t.Fatalf("client did not verify the expected peer certificate: %+v", cs)
	}
	if want, got := l.Addr(), client.RemoteAddr(); want != got {
		t.Fatalf("unexpected client remote address: want %s, got %s", want, got)
	}
	if want, got := client.LocalAddr(), server.RemoteAddr(); want != got {
		t.Fatalf("unexpected server remote address: want %s, got %s", want, got)
	}

	// Client-initiated bidirectional stream: the first is stream 0. Two
	// messages, only the last carrying FIN, arrive in order with FIN only
	// reported once all data has been received.
	sid, err := client.OpenStream(false)
	if err != nil {
		t.Fatalf("failed to open client bidirectional stream: %v", err)
	}
	if sid != 0 || sid.IsServerInitiated() || sid.IsUnidirectional() {
		t.Fatalf("unexpected client bidirectional stream ID: %d", sid)
	}

	send(t, client, sid, 0, "hello, ")
	send(t, client, sid, kquic.StreamFin, "world")
	if want, got := "hello, world", receive(t, server, sid); want != got {
		t.Fatalf("unexpected server data on stream %d: want %q, got %q", sid, want, got)
	}

	// The server can still send on its half of the stream after the
	// client's FIN.
	send(t, server, sid, kquic.StreamFin, "hello, world")
	if want, got := "hello, world", receive(t, client, sid); want != got {
		t.Fatalf("unexpected client data on stream %d: want %q, got %q", sid, want, got)
	}

	// Server-initiated bidirectional stream: the first is stream 1.
	sid, err = server.OpenStream(false)
	if err != nil {
		t.Fatalf("failed to open server bidirectional stream: %v", err)
	}
	if sid != 1 || !sid.IsServerInitiated() || sid.IsUnidirectional() {
		t.Fatalf("unexpected server bidirectional stream ID: %d", sid)
	}

	send(t, server, sid, kquic.StreamFin, "from server")
	if want, got := "from server", receive(t, client, sid); want != got {
		t.Fatalf("unexpected client data on stream %d: want %q, got %q", sid, want, got)
	}

	// Client-initiated unidirectional stream: the first is stream 2, and the
	// server cannot send on it.
	sid, err = client.OpenStream(true)
	if err != nil {
		t.Fatalf("failed to open client unidirectional stream: %v", err)
	}
	if sid != 2 || sid.IsServerInitiated() || !sid.IsUnidirectional() {
		t.Fatalf("unexpected client unidirectional stream ID: %d", sid)
	}

	send(t, client, sid, kquic.StreamFin, "one way")
	if want, got := "one way", receive(t, server, sid); want != got {
		t.Fatalf("unexpected server data on stream %d: want %q, got %q", sid, want, got)
	}
	if _, err := server.Send(sid, kquic.StreamFin, []byte("wrong way")); err == nil {
		t.Fatalf("expected an error sending on peer's unidirectional stream %d", sid)
	}

	// Streams may also be opened implicitly by the first Send with StreamNew,
	// skipping OpenStream. Stream 4 is the next client bidirectional ID.
	sid = 4
	send(t, client, sid, kquic.StreamNew|kquic.StreamFin, "implicit")
	if want, got := "implicit", receive(t, server, sid); want != got {
		t.Fatalf("unexpected server data on stream %d: want %q, got %q", sid, want, got)
	}

	// Invalid flags are rejected before reaching the kernel, wrapped in a
	// *net.OpError like every other error.
	_, err = client.Send(sid, kquic.Flags(1), []byte("bad flags"))
	oerr, ok := errors.AsType[*net.OpError](err)
	if !ok || oerr.Op != "send" || oerr.Net != "quic" {
		t.Fatalf("expected send *net.OpError for invalid flags, but got: %v", err)
	}

	// Closing is clean on both ends, and the connection is unusable after.
	if err := client.Close(); err != nil {
		t.Fatalf("failed to close client: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("failed to close server: %v", err)
	}
	if _, err := client.Send(0, kquic.StreamNew, []byte("closed")); err == nil {
		t.Fatal("expected an error sending on closed client")
	}
	if _, _, _, err := server.Receive(make([]byte, 1)); err == nil {
		t.Fatal("expected an error receiving on closed server")
	}

	if err := l.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}
	if _, err := l.Accept(context.Background()); err == nil {
		t.Fatal("expected an error accepting on closed listener")
	}
}

func TestIntegrationDialCloudflare(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short test mode")
	}
	probe(t)

	// cloudflare-quic.com is Cloudflare's public QUIC/HTTP/3 test server.
	const host = "cloudflare-quic.com"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		t.Skipf("skipping, failed to resolve %q: %v", host, err)
	}

	cfg := &kquic.Config{
		TLSConfig: &tls.Config{
			ServerName: host,
			NextProtos: []string{"h3"},
		},
	}

	// Try each address in turn: a machine may have only one working address
	// family.
	var c *kquic.Conn
	for _, addr := range addrs {
		ap := netip.AddrPortFrom(addr.Unmap(), 443)

		dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
		c, err = kquic.Dial(dctx, ap, cfg)
		dcancel()
		if err == nil {
			break
		}

		t.Logf("failed to dial %s: %v", ap, err)
	}
	if err != nil {
		if isNetworkError(err) {
			t.Skipf("skipping, network error dialing %q: %v", host, err)
		}
		t.Fatalf("failed to dial %q: %v", host, err)
	}
	defer c.Close()

	t.Logf("connected: %s -> %s", c.LocalAddr(), c.RemoteAddr())

	if c.LocalAddr().Port() == 0 || c.RemoteAddr().Port() != 443 {
		t.Fatalf("unexpected addresses: %s -> %s", c.LocalAddr(), c.RemoteAddr())
	}

	cs := c.ConnectionState()
	t.Logf("%s, %s, ALPN %q", tls.VersionName(cs.Version), tls.CipherSuiteName(cs.CipherSuite), cs.NegotiatedProtocol)

	if !cs.HandshakeComplete {
		t.Fatal("handshake not complete")
	}
	if want, got := uint16(tls.VersionTLS13), cs.Version; want != got {
		t.Fatalf("unexpected TLS version: want %s, got %s", tls.VersionName(want), tls.VersionName(got))
	}
	if want, got := "h3", cs.NegotiatedProtocol; want != got {
		t.Fatalf("unexpected ALPN protocol: want %q, got %q", want, got)
	}
	if want, got := host, cs.ServerName; want != got {
		t.Fatalf("unexpected server name: want %q, got %q", want, got)
	}

	// The certificate was verified against the system roots and is valid for
	// the host we dialed.
	if len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
		t.Fatalf("peer certificate was not verified: %d certificates, %d chains",
			len(cs.PeerCertificates), len(cs.VerifiedChains))
	}

	leaf := cs.PeerCertificates[0]
	t.Logf("peer certificate: %s (issuer %s)", leaf.Subject, leaf.Issuer)

	if err := leaf.VerifyHostname(host); err != nil {
		t.Fatalf("peer certificate is not valid for %q: %v", host, err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("failed to close connection: %v", err)
	}
}

// dialAccept concurrently dials l and accepts the connection, returning the
// client and server sides. cert is the listener's certificate, which the
// client pins as its only root.
func dialAccept(t *testing.T, l *kquic.Listener, cert tls.Certificate) (client, server *kquic.Conn) {
	t.Helper()

	// Accept and Dial both complete the handshake before returning, so they
	// must run concurrently. Either side failing cancels the other.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	roots := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	roots.AddCert(leaf)

	type result struct {
		c   *kquic.Conn
		err error
	}

	acceptC := make(chan result, 1)
	go func() {
		c, err := l.Accept(ctx)
		acceptC <- result{c: c, err: err}
	}()

	dialC := make(chan result, 1)
	go func() {
		c, err := kquic.Dial(ctx, l.Addr(), &kquic.Config{
			TLSConfig: &tls.Config{
				RootCAs:    roots,
				NextProtos: []string{alpn},
			},
		})
		dialC <- result{c: c, err: err}
	}()

	var accept, dial result
	for range 2 {
		select {
		case accept = <-acceptC:
			if accept.err != nil {
				cancel()
			}
		case dial = <-dialC:
			if dial.err != nil {
				cancel()
			}
		}
	}

	if accept.err != nil {
		if dial.c != nil {
			_ = dial.c.Close()
		}

		// accept(2) fails with EADDRINUSE for unprivileged users: the
		// child socket is initialized with uid 0 while the listener's
		// tunnel socket carries the caller's uid, so the kernel's uid
		// check rejects the bind. Do not work around it. See:
		// https://github.com/lxin/quic/issues/80.
		if errors.Is(accept.err, unix.EADDRINUSE) && os.Geteuid() != 0 {
			t.Skipf("skipping, non-root accept rejected by kernel uid check bug (https://github.com/lxin/quic/issues/80): %v", accept.err)
		}

		t.Fatalf("failed to accept: %v", accept.err)
	}
	if dial.err != nil {
		_ = accept.c.Close()
		t.Fatalf("failed to dial: %v", dial.err)
	}

	return dial.c, accept.c
}

// send sends s on stream sid of c with flags, requiring the entire message to
// be written.
func send(t *testing.T, c *kquic.Conn, sid kquic.StreamID, flags kquic.Flags, s string) {
	t.Helper()

	n, err := c.Send(sid, flags, []byte(s))
	if err != nil {
		t.Fatalf("%s: failed to send on stream %d: %v", c.LocalAddr(), sid, err)
	}
	if want, got := len(s), n; want != got {
		t.Fatalf("%s: short send on stream %d: want %d bytes, got %d", c.LocalAddr(), sid, want, got)
	}
}

// receive receives from c until the peer finishes stream sid, returning the
// concatenated data. Any data arriving on another stream is a failure.
func receive(t *testing.T, c *kquic.Conn, sid kquic.StreamID) string {
	t.Helper()

	var (
		buf  bytes.Buffer
		b    = make([]byte, 65536)
		fin  bool
		msgs int
	)

	for !fin {
		n, gotSID, flags, err := c.Receive(b)
		if err != nil {
			t.Fatalf("%s: failed to receive on stream %d after %d messages: %v",
				c.LocalAddr(), sid, msgs, err)
		}
		if gotSID != sid {
			t.Fatalf("%s: unexpected stream ID: want %d, got %d (flags %#x, data %q)",
				c.LocalAddr(), sid, gotSID, uint32(flags), b[:n])
		}

		buf.Write(b[:n])
		fin = flags&kquic.StreamFin != 0
		msgs++
	}

	return buf.String()
}

// probeOnce checks once whether the kernel supports QUIC sockets.
var probeOnce = sync.OnceValue(func() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, quicsys.IPPROTO_QUIC)
	if err != nil {
		return os.NewSyscallError("socket", err)
	}

	return unix.Close(fd)
})

// probe skips the test if the kernel does not support QUIC sockets.
func probe(t *testing.T) {
	t.Helper()

	err := probeOnce()
	switch {
	case err == nil:
	case errors.Is(err, unix.EPROTONOSUPPORT), errors.Is(err, unix.EAFNOSUPPORT):
		t.Skipf("skipping, kernel QUIC sockets are not supported (try: 'modprobe quic'): %v", err)
	default:
		t.Fatalf("failed to probe for kernel QUIC socket support: %v", err)
	}
}

// isNetworkError reports whether err indicates that the network is
// unavailable, rather than a problem with the QUIC or TLS implementation.
func isNetworkError(err error) bool {
	if nerr, ok := errors.AsType[net.Error](err); ok && nerr.Timeout() {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	for _, errno := range []unix.Errno{
		unix.ENETUNREACH,
		unix.ENETDOWN,
		unix.EHOSTUNREACH,
		unix.ECONNREFUSED,
		unix.EADDRNOTAVAIL,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}

	return false
}

// selfSignedCert generates an in-memory self-signed certificate valid for
// localhost and the loopback addresses.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kquic"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}
