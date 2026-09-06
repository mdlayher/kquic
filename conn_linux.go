//go:build linux

package kquic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/mdlayher/kquic/internal/quicsys"
	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
)

// name is the socket name passed to package socket.
const name = "quic"

// Verify that the portable Flags constants match the kernel's MSG_QUIC_STREAM_*
// values, so that they can be passed through to the kernel verbatim.
var (
	_ [StreamNew - quicsys.MSG_QUIC_STREAM_NEW]byte
	_ [quicsys.MSG_QUIC_STREAM_NEW - StreamNew]byte
	_ [StreamFin - quicsys.MSG_QUIC_STREAM_FIN]byte
	_ [quicsys.MSG_QUIC_STREAM_FIN - StreamFin]byte
	_ [StreamUni - quicsys.MSG_QUIC_STREAM_UNI]byte
	_ [quicsys.MSG_QUIC_STREAM_UNI - StreamUni]byte
	_ [StreamDontwait - quicsys.MSG_QUIC_STREAM_DONTWAIT]byte
	_ [quicsys.MSG_QUIC_STREAM_DONTWAIT - StreamDontwait]byte
	_ [StreamSndblock - quicsys.MSG_QUIC_STREAM_SNDBLOCK]byte
	_ [quicsys.MSG_QUIC_STREAM_SNDBLOCK - StreamSndblock]byte
)

// streamFlagsMask is the set of Flags bits the kernel accepts in
// quic_stream_info.stream_flags.
const streamFlagsMask = StreamNew | StreamFin | StreamUni | StreamDontwait | StreamSndblock

// A conn is the Linux implementation of a QUIC connection: one socket.Conn is
// one QUIC connection, with streams multiplexed via control messages.
type conn struct {
	c             *socket.Conn
	qc            *tls.QUICConn
	local, remote netip.AddrPort
}

// dial is the entry point for Dial on Linux.
func dial(ctx context.Context, raddr netip.AddrPort, tc *tls.Config) (*conn, error) {
	rsa, err := sockaddr(raddr)
	if err != nil {
		return nil, err
	}

	c, err := quicSocket(raddr.Addr())
	if err != nil {
		return nil, err
	}

	// Be sure to close the socket if anything fails before we return the
	// conn to the caller.

	// The kernel wants the ALPN protocols on the socket as well as in the
	// TLS handshake.
	if err := setALPN(c, tc.NextProtos); err != nil {
		_ = c.Close()
		return nil, err
	}

	if _, err := c.Connect(ctx, rsa); err != nil {
		_ = c.Close()
		return nil, err
	}

	qc := tls.QUICClient(&tls.QUICConfig{TLSConfig: tc})
	if err := handshake(ctx, c, qc); err != nil {
		_ = qc.Close()
		_ = c.Close()
		return nil, err
	}

	cc, err := newConn(c, qc)
	if err != nil {
		_ = qc.Close()
		_ = c.Close()
		return nil, err
	}

	return cc, nil
}

// A listener is the Linux implementation of a QUIC listener.
type listener struct {
	c    *socket.Conn
	tc   *tls.Config
	addr netip.AddrPort
}

// listen is the entry point for Listen on Linux.
func listen(laddr netip.AddrPort, tc *tls.Config) (*listener, error) {
	lsa, err := sockaddr(laddr)
	if err != nil {
		return nil, err
	}

	c, err := quicSocket(laddr.Addr())
	if err != nil {
		return nil, err
	}

	// Be sure to close the socket if anything fails before we return the
	// listener to the caller.

	if err := c.Bind(lsa); err != nil {
		_ = c.Close()
		return nil, err
	}

	// ALPN must be set before listen(2): the kernel uses it to demultiplex
	// incoming connections between listeners.
	if err := setALPN(c, tc.NextProtos); err != nil {
		_ = c.Close()
		return nil, err
	}

	if err := c.Listen(unix.SOMAXCONN); err != nil {
		_ = c.Close()
		return nil, err
	}

	sa, err := c.Getsockname()
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	addr, err := addrPort(sa)
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	return &listener{
		c:    c,
		tc:   tc,
		addr: addr,
	}, nil
}

// accept accepts a single connection and completes the server handshake.
func (l *listener) accept(ctx context.Context) (*conn, error) {
	c, _, err := l.c.Accept(ctx, 0)
	if err != nil {
		return nil, err
	}

	qc := tls.QUICServer(&tls.QUICConfig{TLSConfig: l.tc})
	if err := handshake(ctx, c, qc); err != nil {
		_ = qc.Close()
		_ = c.Close()
		return nil, err
	}

	cc, err := newConn(c, qc)
	if err != nil {
		_ = qc.Close()
		_ = c.Close()
		return nil, err
	}

	return cc, nil
}

func (l *listener) close() error { return l.c.Close() }

// newConn wraps an established socket and its completed TLS handshake.
func newConn(c *socket.Conn, qc *tls.QUICConn) (*conn, error) {
	lsa, err := c.Getsockname()
	if err != nil {
		return nil, err
	}
	local, err := addrPort(lsa)
	if err != nil {
		return nil, err
	}

	rsa, err := c.Getpeername()
	if err != nil {
		return nil, err
	}
	remote, err := addrPort(rsa)
	if err != nil {
		return nil, err
	}

	return &conn{
		c:      c,
		qc:     qc,
		local:  local,
		remote: remote,
	}, nil
}

// quicSocket opens a QUIC socket in the address family of addr.
func quicSocket(addr netip.Addr) (*socket.Conn, error) {
	domain := unix.AF_INET6
	if addr.Is4() {
		domain = unix.AF_INET
	}

	return socket.Socket(domain, unix.SOCK_DGRAM, quicsys.IPPROTO_QUIC, name, nil)
}

// setALPN registers ALPN protocols with the kernel, as a comma-separated list.
func setALPN(c *socket.Conn, protos []string) error {
	for _, p := range protos {
		if strings.ContainsAny(p, ", ") {
			return fmt.Errorf("kquic: invalid ALPN protocol %q", p)
		}
	}

	return c.SetsockoptBytes(quicsys.SOL_QUIC, quicsys.QUIC_SOCKOPT_ALPN, []byte(strings.Join(protos, ",")))
}

func (c *conn) send(sid StreamID, flags Flags, b []byte) (int, error) {
	if flags&^streamFlagsMask != 0 {
		return 0, fmt.Errorf("kquic: invalid stream flags %#x", uint32(flags))
	}

	oob := streamInfoCmsg(quicsys.StreamInfo{
		StreamID:    int64(sid),
		StreamFlags: uint32(flags),
	})

	return c.c.Sendmsg(context.Background(), b, oob, nil, unix.MSG_NOSIGNAL)
}

func (c *conn) receive(b []byte) (int, StreamID, Flags, error) {
	oob := make([]byte, unix.CmsgSpace(int(unsafe.Sizeof(quicsys.StreamInfo{}))))
	for {
		n, oobn, rflags, _, err := c.c.Recvmsg(context.Background(), b, oob, 0)
		if err != nil {
			return 0, 0, 0, err
		}

		// v0 does not enable events or datagrams; discard anything that is
		// not stream data, such as post-handshake CRYPTO messages.
		if rflags&(quicsys.MSG_QUIC_NOTIFICATION|quicsys.MSG_QUIC_DATAGRAM) != 0 {
			continue
		}

		info, ok, err := parseStreamInfo(oob[:oobn])
		if err != nil {
			return 0, 0, 0, err
		}
		if !ok {
			continue
		}

		return n, StreamID(info.StreamID), Flags(info.StreamFlags), nil
	}
}

func (c *conn) openStream(uni bool) (StreamID, error) {
	// quicsys.QUIC_SOCKOPT_STREAM_OPEN is an in/out getsockopt: -1 asks the kernel
	// to assign the next available stream ID, which it writes back.
	info := quicsys.StreamInfo{StreamID: -1}
	if uni {
		info.StreamFlags = quicsys.MSG_QUIC_STREAM_UNI
	}

	b := unsafe.Slice((*byte)(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	n, err := c.c.GetsockoptBytes(quicsys.SOL_QUIC, quicsys.QUIC_SOCKOPT_STREAM_OPEN, b)
	if err != nil {
		return 0, err
	}
	if n != len(b) {
		return 0, fmt.Errorf("kquic: unexpected stream open result length %d", n)
	}

	return StreamID(info.StreamID), nil
}

func (c *conn) connectionState() tls.ConnectionState { return c.qc.ConnectionState() }

func (c *conn) close() error {
	// The kernel sends CONNECTION_CLOSE on close(2).
	_ = c.qc.Close()
	return c.c.Close()
}

func (c *conn) setDeadline(t time.Time) error         { return c.c.SetDeadline(t) }
func (c *conn) setReadDeadline(t time.Time) error     { return c.c.SetReadDeadline(t) }
func (c *conn) setWriteDeadline(t time.Time) error    { return c.c.SetWriteDeadline(t) }
func (c *conn) syscallConn() (syscall.RawConn, error) { return c.c.SyscallConn() }

// streamInfoCmsg encodes info as a quicsys.QUIC_STREAM_INFO control message.
func streamInfoCmsg(info quicsys.StreamInfo) []byte {
	return cmsg(quicsys.QUIC_STREAM_INFO, unsafe.Slice((*byte)(unsafe.Pointer(&info)), unsafe.Sizeof(info)))
}

// handshakeInfoCmsg encodes level as a quicsys.QUIC_HANDSHAKE_INFO control message.
func handshakeInfoCmsg(level uint8) []byte {
	info := quicsys.HandshakeInfo{CryptoLevel: level}
	return cmsg(quicsys.QUIC_HANDSHAKE_INFO, unsafe.Slice((*byte)(unsafe.Pointer(&info)), unsafe.Sizeof(info)))
}

// cmsg encodes a single quicsys.SOL_QUIC control message of type typ carrying data.
func cmsg(typ int, data []byte) []byte {
	b := make([]byte, unix.CmsgSpace(len(data)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = quicsys.SOL_QUIC
	h.Type = int32(typ)
	h.SetLen(unix.CmsgLen(len(data)))
	copy(b[unix.CmsgLen(0):], data)
	return b
}

// parseStreamInfo finds a quicsys.QUIC_STREAM_INFO control message in oob. ok is false
// if none is present.
func parseStreamInfo(oob []byte) (info quicsys.StreamInfo, ok bool, err error) {
	m, err := findCmsg(oob, quicsys.QUIC_STREAM_INFO)
	if err != nil || m == nil {
		return quicsys.StreamInfo{}, false, err
	}
	if len(m.Data) != int(unsafe.Sizeof(info)) {
		return quicsys.StreamInfo{}, false, fmt.Errorf("kquic: unexpected stream info length %d", len(m.Data))
	}

	info = *(*quicsys.StreamInfo)(unsafe.Pointer(&m.Data[0]))
	return info, true, nil
}

// findCmsg returns the quicsys.SOL_QUIC control message of type typ in oob, or nil if
// none is present.
func findCmsg(oob []byte, typ int) (*unix.SocketControlMessage, error) {
	if len(oob) == 0 {
		return nil, nil
	}

	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, os.NewSyscallError("parse-cmsg", err)
	}

	for i := range msgs {
		if msgs[i].Header.Level == quicsys.SOL_QUIC && msgs[i].Header.Type == int32(typ) {
			return &msgs[i], nil
		}
	}

	return nil, nil
}

// sockaddr converts ap to a unix.Sockaddr.
func sockaddr(ap netip.AddrPort) (unix.Sockaddr, error) {
	if !ap.IsValid() {
		return nil, fmt.Errorf("kquic: invalid address %q", ap)
	}

	addr := ap.Addr()
	if addr.Is4() {
		return &unix.SockaddrInet4{
			Port: int(ap.Port()),
			Addr: addr.As4(),
		}, nil
	}

	sa := &unix.SockaddrInet6{
		Port: int(ap.Port()),
		Addr: addr.As16(),
	}
	if zone := addr.Zone(); zone != "" {
		ifi, err := net.InterfaceByName(zone)
		if err != nil {
			return nil, err
		}
		sa.ZoneId = uint32(ifi.Index)
	}

	return sa, nil
}

// addrPort converts sa to a netip.AddrPort.
func addrPort(sa unix.Sockaddr) (netip.AddrPort, error) {
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port)), nil
	case *unix.SockaddrInet6:
		addr := netip.AddrFrom16(sa.Addr)
		if sa.ZoneId != 0 {
			if ifi, err := net.InterfaceByIndex(int(sa.ZoneId)); err == nil {
				addr = addr.WithZone(ifi.Name)
			}
		}
		return netip.AddrPortFrom(addr, uint16(sa.Port)), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("kquic: unexpected sockaddr type %T", sa)
	}
}
