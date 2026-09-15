//go:build linux

package kquic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"github.com/mdlayher/socket"

	"github.com/mdlayher/kquic/internal/quicsys"
	"golang.org/x/sys/unix"
)

const (
	// maxTransportParamExt is the buffer size used to fetch the kernel's
	// encoded local transport parameters extension.
	maxTransportParamExt = 512

	// maxHandshakeMsg is the buffer size for a single received handshake
	// message, matching libquic.
	maxHandshakeMsg = 65536
)

// handshake drives the TLS 1.3 handshake on qc over the socket c, mapping
// crypto/tls QUIC events onto kernel operations:
//
//   - the kernel's local transport parameters seed the handshake
//   - CRYPTO data is exchanged via sendmsg/recvmsg with quicsys.QUIC_HANDSHAKE_INFO
//   - traffic secrets are installed via quicsys.QUIC_SOCKOPT_CRYPTO_SECRET
//   - the peer's transport parameters are set via quicsys.QUIC_SOCKOPT_TRANSPORT_PARAM_EXT
//
// crypto/tls reports QUICHandshakeDone before it provides the 1-RTT read
// secret, which RFC 9001, section 5.7 requires a QUIC layer not to use any
// earlier, so the loop drains the remaining events and exits once the queue
// is empty.
func handshake(ctx context.Context, c *socket.Conn, qc *tls.QUICConn) error {
	// Local transport parameters are owned and encoded by the kernel.
	tp := make([]byte, maxTransportParamExt)
	n, err := c.GetsockoptBytes(quicsys.SOL_QUIC, quicsys.QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, tp)
	if err != nil {
		return err
	}
	if n > len(tp) {
		return io.ErrShortBuffer
	}
	qc.SetTransportParameters(tp[:n])

	if err := qc.Start(ctx); err != nil {
		return err
	}

	buf := make([]byte, maxHandshakeMsg)
	var done bool
	for {
		ev := qc.NextEvent()
		if err, ok := errorEvent(ev); ok {
			return err
		}

		switch ev.Kind {
		case tls.QUICNoEvent:
			// Once the handshake is done, an empty queue means every
			// secret has been installed and there is nothing left to read.
			if done {
				return nil
			}

			// crypto/tls needs more input from the peer.
			level, data, err := recvHandshake(ctx, c, buf)
			if err != nil {
				return err
			}
			if err := qc.HandleData(level, data); err != nil {
				return err
			}
		case tls.QUICWriteData:
			if err := sendHandshake(ctx, c, ev.Level, ev.Data); err != nil {
				return err
			}
		case tls.QUICSetReadSecret:
			if err := setSecret(c, false, ev.Level, ev.Suite, ev.Data); err != nil {
				return err
			}
		case tls.QUICSetWriteSecret:
			if err := setSecret(c, true, ev.Level, ev.Suite, ev.Data); err != nil {
				return err
			}
		case tls.QUICTransportParameters:
			if err := c.SetsockoptBytes(quicsys.SOL_QUIC, quicsys.QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, ev.Data); err != nil {
				return err
			}
		case tls.QUICTransportParametersRequired:
			// Cannot happen: parameters are set before Start.
			return errors.New("kquic: transport parameters unexpectedly required")
		case tls.QUICHandshakeDone:
			// The application read secret is still queued behind this
			// event; keep draining rather than returning here.
			done = true
		case tls.QUICRejectedEarlyData, tls.QUICResumeSession, tls.QUICStoreSession:
			// Session resumption and 0-RTT are not supported in v0; these
			// events require no action.
		default:
			return fmt.Errorf("kquic: unhandled TLS QUIC event %d", ev.Kind)
		}
	}
}

// sendHandshake sends CRYPTO data at the given encryption level.
func sendHandshake(ctx context.Context, c *socket.Conn, level tls.QUICEncryptionLevel, data []byte) error {
	klevel, err := cryptoLevel(level)
	if err != nil {
		return err
	}

	n, err := c.Sendmsg(ctx, data, handshakeInfoCmsg(klevel), nil, unix.MSG_NOSIGNAL)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}

	return nil
}

// recvHandshake receives one CRYPTO message from the peer, returning its
// encryption level and data. The returned data aliases buf.
func recvHandshake(ctx context.Context, c *socket.Conn, buf []byte) (tls.QUICEncryptionLevel, []byte, error) {
	oob := make([]byte, unix.CmsgSpace(int(unsafe.Sizeof(quicsys.HandshakeInfo{}))))
	n, oobn, rflags, _, err := c.Recvmsg(ctx, buf, oob, 0)
	if err != nil {
		return 0, nil, err
	}
	if n == 0 {
		return 0, nil, io.ErrUnexpectedEOF
	}
	if rflags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return 0, nil, os.NewSyscallError("recvmsg", unix.EMSGSIZE)
	}

	m, err := findCmsg(oob[:oobn], quicsys.QUIC_HANDSHAKE_INFO)
	if err != nil {
		return 0, nil, err
	}
	if m == nil {
		return 0, nil, errors.New("kquic: received non-handshake data during handshake")
	}
	if len(m.Data) < int(unsafe.Sizeof(quicsys.HandshakeInfo{})) {
		return 0, nil, fmt.Errorf("kquic: unexpected handshake info length %d", len(m.Data))
	}

	level, err := tlsLevel(m.Data[0])
	if err != nil {
		return 0, nil, err
	}

	return level, buf[:n], nil
}

// setSecret installs a traffic secret for one encryption level and direction.
func setSecret(c *socket.Conn, send bool, level tls.QUICEncryptionLevel, suite uint16, secret []byte) error {
	klevel, err := cryptoLevel(level)
	if err != nil {
		return err
	}

	typ, err := cipherType(suite)
	if err != nil {
		return err
	}

	if len(secret) > quicsys.QUIC_CRYPTO_SECRET_BUFFER_SIZE {
		return fmt.Errorf("kquic: secret length %d exceeds kernel buffer", len(secret))
	}

	s := quicsys.CryptoSecret{
		Level: klevel,
		Type:  typ,
	}
	if send {
		s.Send = 1
	}
	copy(s.Secret[:], secret)

	b := unsafe.Slice((*byte)(unsafe.Pointer(&s)), unsafe.Sizeof(s))
	err = c.SetsockoptBytes(quicsys.SOL_QUIC, quicsys.QUIC_SOCKOPT_CRYPTO_SECRET, b)
	clear(s.Secret[:])
	return err
}

// errorEvent reports whether ev is a fatal tls.QUICErrorEvent, returning its
// error.
func errorEvent(ev tls.QUICEvent) (error, bool) {
	if ev.Kind != tls.QUICErrorEvent {
		return nil, false
	}

	return ev.Err, true
}

// cryptoLevel maps a crypto/tls encryption level to a kernel crypto level.
func cryptoLevel(level tls.QUICEncryptionLevel) (uint8, error) {
	switch level {
	case tls.QUICEncryptionLevelInitial:
		return quicsys.QUIC_CRYPTO_INITIAL, nil
	case tls.QUICEncryptionLevelEarly:
		return quicsys.QUIC_CRYPTO_EARLY, nil
	case tls.QUICEncryptionLevelHandshake:
		return quicsys.QUIC_CRYPTO_HANDSHAKE, nil
	case tls.QUICEncryptionLevelApplication:
		return quicsys.QUIC_CRYPTO_APP, nil
	default:
		return 0, fmt.Errorf("kquic: unknown TLS encryption level %d", level)
	}
}

// tlsLevel maps a kernel crypto level to a crypto/tls encryption level.
func tlsLevel(level uint8) (tls.QUICEncryptionLevel, error) {
	switch level {
	case quicsys.QUIC_CRYPTO_INITIAL:
		return tls.QUICEncryptionLevelInitial, nil
	case quicsys.QUIC_CRYPTO_EARLY:
		return tls.QUICEncryptionLevelEarly, nil
	case quicsys.QUIC_CRYPTO_HANDSHAKE:
		return tls.QUICEncryptionLevelHandshake, nil
	case quicsys.QUIC_CRYPTO_APP:
		return tls.QUICEncryptionLevelApplication, nil
	default:
		return 0, fmt.Errorf("kquic: unknown kernel crypto level %d", level)
	}
}

// cipherType maps a TLS 1.3 cipher suite to a kernel TLS_CIPHER_* type.
func cipherType(suite uint16) (uint32, error) {
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
		return quicsys.TLS_CIPHER_AES_GCM_128, nil
	case tls.TLS_AES_256_GCM_SHA384:
		return quicsys.TLS_CIPHER_AES_GCM_256, nil
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return quicsys.TLS_CIPHER_CHACHA20_POLY1305, nil
	default:
		return 0, fmt.Errorf("kquic: unsupported TLS cipher suite %#04x", suite)
	}
}
