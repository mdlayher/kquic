package kquic_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/mdlayher/kquic"
)

func TestConfigErrors(t *testing.T) {
	// Configuration is validated before any socket is created, so these
	// tests run on every platform without kernel QUIC support.
	tests := []struct {
		name string
		cfg  *kquic.Config
	}{
		{
			name: "nil config",
		},
		{
			name: "nil TLS config",
			cfg:  &kquic.Config{},
		},
		{
			name: "no ALPN",
			cfg: &kquic.Config{
				TLSConfig: &tls.Config{},
			},
		},
		{
			name: "TLS 1.2 maximum",
			cfg: &kquic.Config{
				TLSConfig: &tls.Config{
					NextProtos: []string{"h3"},
					MaxVersion: tls.VersionTLS12,
				},
			},
		},
	}

	ap := netip.MustParseAddrPort("127.0.0.1:0")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := kquic.Dial(context.Background(), ap, tt.cfg)
			checkOpError(t, "dial", err)

			_, err = kquic.Listen(ap, tt.cfg)
			checkOpError(t, "listen", err)
		})
	}
}

// checkOpError requires err to be a *net.OpError for the QUIC network with
// the given operation.
func checkOpError(t *testing.T, op string, err error) {
	t.Helper()

	oerr, ok := errors.AsType[*net.OpError](err)
	if !ok {
		t.Fatalf("expected *net.OpError from %s, but got: %v", op, err)
	}

	if want, got := op, oerr.Op; want != got {
		t.Fatalf("unexpected operation: want %q, got %q", want, got)
	}
	if want, got := "quic", oerr.Net; want != got {
		t.Fatalf("unexpected network: want %q, got %q", want, got)
	}
}
