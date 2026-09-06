//go:build !linux

package kquic

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestUnimplemented(t *testing.T) {
	ap := netip.MustParseAddrPort("127.0.0.1:0")

	if _, err := listen(ap, nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("unexpected error from listen: %v", err)
	}

	if _, err := dial(context.Background(), ap, nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("unexpected error from dial: %v", err)
	}

	// Every method on the stub types reports the same error.
	var (
		l listener
		c conn
	)

	if err := l.close(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("unexpected error from listener close: %v", err)
	}

	if err := c.close(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("unexpected error from conn close: %v", err)
	}
}
