package kquic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

const (
	// network is the network reported in net.OpError.
	network = "quic"

	// Operation names which may be returned in net.OpError.
	opAccept      = "accept"
	opClose       = "close"
	opDial        = "dial"
	opListen      = "listen"
	opOpenStream  = "open-stream"
	opReceive     = "receive"
	opSend        = "send"
	opSet         = "set"
	opSyscallConn = "syscall-conn"
)

// Config configures a Conn or Listener.
type Config struct {
	// TLSConfig is the TLS configuration used to perform the TLS 1.3 handshake
	// in userspace. It is required and must set NextProtos (ALPN). MinVersion
	// is defaulted to TLS 1.3 when unset; lower versions are rejected.
	//
	// The kernel uses the ALPN protocols from NextProtos to demultiplex
	// incoming connections between listeners.
	TLSConfig *tls.Config
}

// tlsConfig validates cfg and returns a cloned *tls.Config suitable for QUIC.
func tlsConfig(cfg *Config) (*tls.Config, error) {
	if cfg == nil || cfg.TLSConfig == nil {
		return nil, errors.New("kquic: Config.TLSConfig is required")
	}

	tc := cfg.TLSConfig.Clone()
	if len(tc.NextProtos) == 0 {
		return nil, errors.New("kquic: Config.TLSConfig.NextProtos (ALPN) is required")
	}

	if tc.MinVersion < tls.VersionTLS13 {
		tc.MinVersion = tls.VersionTLS13
	}
	if tc.MaxVersion != 0 && tc.MaxVersion < tls.VersionTLS13 {
		return nil, errors.New("kquic: Config.TLSConfig.MaxVersion must allow TLS 1.3")
	}

	return tc, nil
}

// A StreamID identifies a QUIC stream. Client-initiated bidirectional streams
// are 0, 4, 8, ...; server-initiated bidirectional streams are 1, 5, 9, ...;
// unidirectional streams add 2. The two low bits carry the type.
type StreamID int64

// IsServerInitiated reports whether the stream was initiated by the server.
func (id StreamID) IsServerInitiated() bool { return id&0x01 != 0 }

// IsUnidirectional reports whether the stream is unidirectional.
func (id StreamID) IsUnidirectional() bool { return id&0x02 != 0 }

// Flags are per-message stream flags for Conn.Send and Conn.Receive.
type Flags uint32

// Possible Flags values. These alias the kernel's MSG_QUIC_STREAM_* flags,
// which in turn alias existing Linux MSG_* bits.
const (
	// StreamNew opens the stream on its first send. Use it with the first
	// message on a new stream ID, or open the stream with Conn.OpenStream.
	StreamNew Flags = 0x400 // MSG_SYN

	// StreamFin marks the final message on a stream. On receive, it reports
	// that the peer finished the stream.
	StreamFin Flags = 0x200 // MSG_FIN

	// StreamUni opens a unidirectional stream, in combination with StreamNew.
	StreamUni Flags = 0x800 // MSG_CONFIRM

	// StreamDontwait makes a send return immediately rather than blocking
	// when the stream is not yet available.
	StreamDontwait Flags = 0x80 // MSG_EOR

	// StreamSndblock blocks a send until the stream's data is acknowledged.
	StreamSndblock Flags = 0x2000 // MSG_ERRQUEUE
)

// Dial dials a QUIC connection to raddr and completes the QUIC/TLS handshake
// before returning. cfg is required.
//
// If cfg.TLSConfig.ServerName is empty and InsecureSkipVerify is false, the
// server name is defaulted to raddr's IP address for certificate verification.
func Dial(ctx context.Context, raddr netip.AddrPort, cfg *Config) (*Conn, error) {
	tc, err := tlsConfig(cfg)
	if err != nil {
		return nil, opError(opDial, err, netip.AddrPort{}, raddr)
	}
	if tc.ServerName == "" {
		tc.ServerName = raddr.Addr().String()
	}

	c, err := dial(ctx, raddr, tc)
	if err != nil {
		return nil, opError(opDial, err, netip.AddrPort{}, raddr)
	}

	return &Conn{c: c}, nil
}

// Listen listens for incoming QUIC connections on laddr. cfg is required, and
// the ALPN protocols in cfg.TLSConfig.NextProtos are registered with the kernel
// to demultiplex incoming connections to this Listener.
func Listen(laddr netip.AddrPort, cfg *Config) (*Listener, error) {
	tc, err := tlsConfig(cfg)
	if err != nil {
		return nil, opError(opListen, err, laddr, netip.AddrPort{})
	}

	l, err := listen(laddr, tc)
	if err != nil {
		return nil, opError(opListen, err, laddr, netip.AddrPort{})
	}

	return &Listener{l: l}, nil
}

// A Listener listens for incoming QUIC connections.
type Listener struct {
	l *listener
}

// Accept accepts a connection and completes the server side of the QUIC/TLS
// handshake before returning. Handshakes are serialized: Accept does not
// return until the accepted connection is established.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	c, err := l.l.accept(ctx)
	if err != nil {
		return nil, opError(opAccept, err, l.l.addr, netip.AddrPort{})
	}

	return &Conn{c: c}, nil
}

// Addr returns the local address of the Listener.
func (l *Listener) Addr() netip.AddrPort { return l.l.addr }

// Close stops listening. Already accepted connections are not closed.
func (l *Listener) Close() error {
	return opError(opClose, l.l.close(), l.l.addr, netip.AddrPort{})
}

var _ syscall.Conn = &Conn{}

// A Conn is a QUIC connection. The kernel multiplexes streams over the
// connection: each Send or Receive carries one message on one stream.
type Conn struct {
	c *conn
}

// Send writes one message on stream sid. Pass StreamNew with the first message
// on a stream that was not opened with OpenStream, and StreamFin with the final
// message.
func (c *Conn) Send(sid StreamID, flags Flags, b []byte) (int, error) {
	n, err := c.c.send(sid, flags, b)
	return n, c.opError(opSend, err)
}

// Receive reads one message from the connection into b, reporting the stream
// it arrived on and its flags. StreamFin is set when the peer finished the
// stream. If b is too small for the message, the remainder is returned by
// subsequent calls.
func (c *Conn) Receive(b []byte) (n int, sid StreamID, flags Flags, err error) {
	n, sid, flags, err = c.c.receive(b)
	return n, sid, flags, c.opError(opReceive, err)
}

// OpenStream opens the next available bidirectional or unidirectional stream
// and returns its ID.
func (c *Conn) OpenStream(uni bool) (StreamID, error) {
	sid, err := c.c.openStream(uni)
	return sid, c.opError(opOpenStream, err)
}

// ConnectionState returns the TLS connection state of the completed handshake.
func (c *Conn) ConnectionState() tls.ConnectionState { return c.c.connectionState() }

// LocalAddr returns the local address of the connection.
func (c *Conn) LocalAddr() netip.AddrPort { return c.c.local }

// RemoteAddr returns the remote address of the connection.
func (c *Conn) RemoteAddr() netip.AddrPort { return c.c.remote }

// Close closes the connection.
func (c *Conn) Close() error { return c.opError(opClose, c.c.close()) }

// SetDeadline sets the read and write deadlines for the connection.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.opError(opSet, c.c.setDeadline(t))
}

// SetReadDeadline sets the read deadline for the connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.opError(opSet, c.c.setReadDeadline(t))
}

// SetWriteDeadline sets the write deadline for the connection.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.opError(opSet, c.c.setWriteDeadline(t))
}

// SyscallConn returns a raw network connection for direct access to the
// underlying socket.
func (c *Conn) SyscallConn() (syscall.RawConn, error) {
	rc, err := c.c.syscallConn()
	return rc, c.opError(opSyscallConn, err)
}

// opError is a convenience for opError with the addresses of c.
func (c *Conn) opError(op string, err error) error {
	return opError(op, err, c.c.local, c.c.remote)
}

// opError wraps err in a *net.OpError for the QUIC network, unless err is nil
// or already a *net.OpError.
func opError(op string, err error, local, remote netip.AddrPort) error {
	if err == nil {
		return nil
	}

	if _, ok := errors.AsType[*net.OpError](err); ok {
		return err
	}

	return &net.OpError{
		Op:     op,
		Net:    network,
		Source: udpAddr(local),
		Addr:   udpAddr(remote),
		Err:    err,
	}
}

// udpAddr converts ap to a net.Addr, or nil if ap is invalid. QUIC runs over
// UDP, so *net.UDPAddr is the natural representation.
func udpAddr(ap netip.AddrPort) net.Addr {
	if !ap.IsValid() {
		return nil
	}

	return net.UDPAddrFromAddrPort(ap)
}
