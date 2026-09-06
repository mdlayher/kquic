//go:build linux

package kquic

import (
	"crypto/tls"
	"errors"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/mdlayher/kquic/internal/quicsys"
	"golang.org/x/sys/unix"
)

func TestSockaddrRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		ap   netip.AddrPort
		sa   unix.Sockaddr
	}{
		{
			name: "IPv4",
			ap:   netip.MustParseAddrPort("127.0.0.1:443"),
			sa: &unix.SockaddrInet4{
				Port: 443,
				Addr: [4]byte{127, 0, 0, 1},
			},
		},
		{
			name: "IPv6",
			ap:   netip.MustParseAddrPort("[2001:db8::1]:443"),
			sa: &unix.SockaddrInet6{
				Port: 443,
				Addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 0x01},
			},
		},
		{
			name: "IPv6 zone",
			// Every Linux machine has loopback at interface index 1.
			ap: netip.MustParseAddrPort("[fe80::1%lo]:443"),
			sa: &unix.SockaddrInet6{
				Port:   443,
				Addr:   [16]byte{0xfe, 0x80, 15: 0x01},
				ZoneId: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa, err := sockaddr(tt.ap)
			if err != nil {
				t.Fatalf("failed to convert to sockaddr: %v", err)
			}

			switch sa := sa.(type) {
			case *unix.SockaddrInet4:
				if want, got := *tt.sa.(*unix.SockaddrInet4), *sa; want != got {
					t.Fatalf("unexpected sockaddr: want %+v, got %+v", want, got)
				}
			case *unix.SockaddrInet6:
				if want, got := *tt.sa.(*unix.SockaddrInet6), *sa; want != got {
					t.Fatalf("unexpected sockaddr: want %+v, got %+v", want, got)
				}
			default:
				t.Fatalf("unexpected sockaddr type: %T", sa)
			}

			ap, err := addrPort(sa)
			if err != nil {
				t.Fatalf("failed to convert to netip.AddrPort: %v", err)
			}
			if want, got := tt.ap, ap; want != got {
				t.Fatalf("unexpected round trip: want %s, got %s", want, got)
			}
		})
	}
}

func TestSockaddrErrors(t *testing.T) {
	tests := []struct {
		name string
		ap   netip.AddrPort
	}{
		{
			name: "invalid",
		},
		{
			name: "unknown zone",
			ap:   netip.MustParseAddrPort("[fe80::1%kquicnosuchif0]:443"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := sockaddr(tt.ap); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}

	t.Run("unexpected sockaddr", func(t *testing.T) {
		if _, err := addrPort(&unix.SockaddrUnix{Name: "/kquic"}); err == nil {
			t.Fatal("expected an error, but none occurred")
		}
	})
}

func TestStreamInfoCmsg(t *testing.T) {
	info := quicsys.StreamInfo{
		StreamID:    4,
		StreamFlags: uint32(StreamNew | StreamFin),
	}

	// A control message for a different socket level must be skipped over
	// to find ours.
	other := cmsg(0, make([]byte, 4))
	(*unix.Cmsghdr)(unsafe.Pointer(&other[0])).Level = unix.SOL_SOCKET

	tests := []struct {
		name string
		oob  []byte
		info quicsys.StreamInfo
		ok   bool
	}{
		{
			name: "empty",
		},
		{
			name: "other level",
			oob:  other,
		},
		{
			name: "handshake info",
			oob:  handshakeInfoCmsg(quicsys.QUIC_CRYPTO_INITIAL),
		},
		{
			name: "stream info",
			oob:  streamInfoCmsg(info),
			info: info,
			ok:   true,
		},
		{
			name: "stream info after other level",
			oob:  append(other, streamInfoCmsg(info)...),
			info: info,
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := parseStreamInfo(tt.oob)
			if err != nil {
				t.Fatalf("failed to parse stream info: %v", err)
			}
			if want, got := tt.ok, ok; want != got {
				t.Fatalf("unexpected ok: want %v, got %v", want, got)
			}
			if want, got := tt.info, got; want != got {
				t.Fatalf("unexpected stream info: want %+v, got %+v", want, got)
			}
		})
	}
}

func TestStreamInfoCmsgErrors(t *testing.T) {
	t.Run("short data", func(t *testing.T) {
		_, _, err := parseStreamInfo(cmsg(quicsys.QUIC_STREAM_INFO, make([]byte, 8)))
		if err == nil {
			t.Fatal("expected an error, but none occurred")
		}
	})

	t.Run("malformed", func(t *testing.T) {
		// A header whose length field is smaller than the header itself.
		_, _, err := parseStreamInfo(make([]byte, unix.SizeofCmsghdr))
		if !errors.Is(err, unix.EINVAL) {
			t.Fatalf("expected EINVAL, but got: %v", err)
		}
	})
}

func TestHandshakeInfoCmsg(t *testing.T) {
	m, err := findCmsg(handshakeInfoCmsg(quicsys.QUIC_CRYPTO_HANDSHAKE), quicsys.QUIC_HANDSHAKE_INFO)
	if err != nil {
		t.Fatalf("failed to find handshake info: %v", err)
	}
	if m == nil {
		t.Fatal("handshake info not found")
	}

	if want, got := int32(quicsys.SOL_QUIC), m.Header.Level; want != got {
		t.Fatalf("unexpected level: want %d, got %d", want, got)
	}
	if want, got := []byte{quicsys.QUIC_CRYPTO_HANDSHAKE}, m.Data; string(want) != string(got) {
		t.Fatalf("unexpected data: want %v, got %v", want, got)
	}
}

func TestCryptoLevels(t *testing.T) {
	tests := []struct {
		tls    tls.QUICEncryptionLevel
		kernel uint8
	}{
		{tls: tls.QUICEncryptionLevelInitial, kernel: quicsys.QUIC_CRYPTO_INITIAL},
		{tls: tls.QUICEncryptionLevelEarly, kernel: quicsys.QUIC_CRYPTO_EARLY},
		{tls: tls.QUICEncryptionLevelHandshake, kernel: quicsys.QUIC_CRYPTO_HANDSHAKE},
		{tls: tls.QUICEncryptionLevelApplication, kernel: quicsys.QUIC_CRYPTO_APP},
	}

	for _, tt := range tests {
		t.Run(tt.tls.String(), func(t *testing.T) {
			kernel, err := cryptoLevel(tt.tls)
			if err != nil {
				t.Fatalf("failed to map TLS level: %v", err)
			}
			if want, got := tt.kernel, kernel; want != got {
				t.Fatalf("unexpected kernel level: want %d, got %d", want, got)
			}

			level, err := tlsLevel(kernel)
			if err != nil {
				t.Fatalf("failed to map kernel level: %v", err)
			}
			if want, got := tt.tls, level; want != got {
				t.Fatalf("unexpected TLS level: want %s, got %s", want, got)
			}
		})
	}

	t.Run("unknown", func(t *testing.T) {
		if _, err := cryptoLevel(tls.QUICEncryptionLevel(99)); err == nil {
			t.Fatal("expected an error for unknown TLS level")
		}
		if _, err := tlsLevel(quicsys.QUIC_CRYPTO_MAX); err == nil {
			t.Fatal("expected an error for unknown kernel level")
		}
	})
}

func TestCipherType(t *testing.T) {
	tests := []struct {
		suite  uint16
		kernel uint32
		ok     bool
	}{
		{suite: tls.TLS_AES_128_GCM_SHA256, kernel: quicsys.TLS_CIPHER_AES_GCM_128, ok: true},
		{suite: tls.TLS_AES_256_GCM_SHA384, kernel: quicsys.TLS_CIPHER_AES_GCM_256, ok: true},
		{suite: tls.TLS_CHACHA20_POLY1305_SHA256, kernel: quicsys.TLS_CIPHER_CHACHA20_POLY1305, ok: true},
		// TLS 1.2 suites are never negotiated, but must be rejected.
		{suite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}

	for _, tt := range tests {
		t.Run(tls.CipherSuiteName(tt.suite), func(t *testing.T) {
			kernel, err := cipherType(tt.suite)
			if tt.ok != (err == nil) {
				t.Fatalf("unexpected error: %v", err)
			}
			if want, got := tt.kernel, kernel; want != got {
				t.Fatalf("unexpected kernel cipher type: want %d, got %d", want, got)
			}
		})
	}
}

func TestErrorEvent(t *testing.T) {
	if err, ok := errorEvent(tls.QUICEvent{Kind: tls.QUICHandshakeDone}); ok || err != nil {
		t.Fatalf("expected no error event, but got: %v", err)
	}

	errFoo := errors.New("foo")
	if err, ok := errorEvent(tls.QUICEvent{Kind: tls.QUICErrorEvent, Err: errFoo}); !ok || err != errFoo {
		t.Fatalf("expected error event, but got: %v", err)
	}
}

func TestValidationBeforeSyscall(t *testing.T) {
	// These checks must fail before the (nil) socket is ever touched.

	t.Run("ALPN", func(t *testing.T) {
		for _, protos := range [][]string{{"h3,h3-29"}, {"h3", "not okay"}} {
			if err := setALPN(nil, protos); err == nil {
				t.Fatalf("expected an error for ALPN protocols %q", protos)
			}
		}
	})

	t.Run("stream flags", func(t *testing.T) {
		c := &conn{}
		if _, err := c.send(0, Flags(1), nil); err == nil {
			t.Fatal("expected an error for invalid stream flags")
		}
	})
}
