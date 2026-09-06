package kquic

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
)

func TestStreamID(t *testing.T) {
	tests := []struct {
		id          StreamID
		server, uni bool
	}{
		{id: 0},
		{id: 1, server: true},
		{id: 2, uni: true},
		{id: 3, server: true, uni: true},
		{id: 4},
		{id: 5, server: true},
		{id: 6, uni: true},
		{id: 7, server: true, uni: true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.id), func(t *testing.T) {
			if want, got := tt.server, tt.id.IsServerInitiated(); want != got {
				t.Fatalf("unexpected IsServerInitiated: want %v, got %v", want, got)
			}
			if want, got := tt.uni, tt.id.IsUnidirectional(); want != got {
				t.Fatalf("unexpected IsUnidirectional: want %v, got %v", want, got)
			}
		})
	}
}

func TestTLSConfigDefaults(t *testing.T) {
	tests := []struct {
		name string
		min  uint16
		want uint16
	}{
		{
			name: "unset",
			want: tls.VersionTLS13,
		},
		{
			name: "TLS 1.2",
			min:  tls.VersionTLS12,
			want: tls.VersionTLS13,
		},
		{
			name: "TLS 1.3",
			min:  tls.VersionTLS13,
			want: tls.VersionTLS13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := &tls.Config{
				MinVersion: tt.min,
				NextProtos: []string{"h3"},
			}

			tc, err := tlsConfig(&Config{TLSConfig: in})
			if err != nil {
				t.Fatalf("failed to validate config: %v", err)
			}

			if want, got := tt.want, tc.MinVersion; want != got {
				t.Fatalf("unexpected MinVersion: want %s, got %s",
					tls.VersionName(want), tls.VersionName(got))
			}
			if want, got := "h3", tc.NextProtos[0]; want != got {
				t.Fatalf("unexpected ALPN protocol: want %q, got %q", want, got)
			}

			// The caller's configuration is cloned, never modified.
			if tc == in {
				t.Fatal("expected a cloned TLS config")
			}
			if want, got := tt.min, in.MinVersion; want != got {
				t.Fatalf("caller's MinVersion was modified: want %s, got %s",
					tls.VersionName(want), tls.VersionName(got))
			}
		})
	}
}

func TestOpError(t *testing.T) {
	var (
		local  = netip.MustParseAddrPort("127.0.0.1:1")
		remote = netip.MustParseAddrPort("[::1]:2")
		errFoo = errors.New("foo")
	)

	t.Run("nil", func(t *testing.T) {
		if err := opError(opSend, nil, local, remote); err != nil {
			t.Fatalf("expected nil error, but got: %v", err)
		}
	})

	t.Run("wrapped", func(t *testing.T) {
		// Errors already carrying a *net.OpError are returned unchanged,
		// even when wrapped, to avoid double wrapping.
		oerr := &net.OpError{Op: opReceive, Net: network, Err: errFoo}
		in := fmt.Errorf("wrapped: %w", oerr)

		if err := opError(opSend, in, local, remote); err != in {
			t.Fatalf("expected error to be returned as-is, but got: %v", err)
		}
	})

	t.Run("addresses", func(t *testing.T) {
		err := opError(opSend, errFoo, local, remote)

		oerr, ok := errors.AsType[*net.OpError](err)
		if !ok {
			t.Fatalf("expected *net.OpError, but got: %T", err)
		}
		if !errors.Is(err, errFoo) {
			t.Fatalf("expected wrapped error, but got: %v", err)
		}

		if want, got := opSend, oerr.Op; want != got {
			t.Fatalf("unexpected Op: want %q, got %q", want, got)
		}
		if want, got := network, oerr.Net; want != got {
			t.Fatalf("unexpected Net: want %q, got %q", want, got)
		}

		src, ok := oerr.Source.(*net.UDPAddr)
		if !ok || src.AddrPort() != local {
			t.Fatalf("unexpected Source: %v", oerr.Source)
		}
		dst, ok := oerr.Addr.(*net.UDPAddr)
		if !ok || dst.AddrPort() != remote {
			t.Fatalf("unexpected Addr: %v", oerr.Addr)
		}
	})

	t.Run("invalid addresses", func(t *testing.T) {
		// A Dial error has no local address; a Listen error has no remote
		// address. Neither must produce a non-nil net.Addr.
		err := opError(opDial, errFoo, netip.AddrPort{}, netip.AddrPort{})

		oerr, ok := errors.AsType[*net.OpError](err)
		if !ok {
			t.Fatalf("expected *net.OpError, but got: %T", err)
		}
		if oerr.Source != nil || oerr.Addr != nil {
			t.Fatalf("expected nil addresses, but got: %v, %v", oerr.Source, oerr.Addr)
		}
	})
}
