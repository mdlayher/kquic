//go:build !linux

package kquic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"syscall"
	"time"
)

// errUnimplemented is returned by all functions on platforms that cannot make
// use of kernel QUIC sockets.
var errUnimplemented = fmt.Errorf("kquic: not implemented on %s/%s: %w", runtime.GOOS, runtime.GOARCH, errors.ErrUnsupported)

func dial(_ context.Context, _ netip.AddrPort, _ *tls.Config) (*conn, error) {
	return nil, errUnimplemented
}

func listen(_ netip.AddrPort, _ *tls.Config) (*listener, error) { return nil, errUnimplemented }

type listener struct {
	addr netip.AddrPort
}

func (*listener) accept(_ context.Context) (*conn, error) { return nil, errUnimplemented }
func (*listener) close() error                            { return errUnimplemented }

type conn struct {
	local, remote netip.AddrPort
}

func (*conn) send(_ StreamID, _ Flags, _ []byte) (int, error) { return 0, errUnimplemented }
func (*conn) receive(_ []byte) (int, StreamID, Flags, error)  { return 0, 0, 0, errUnimplemented }
func (*conn) openStream(_ bool) (StreamID, error)             { return 0, errUnimplemented }
func (*conn) connectionState() tls.ConnectionState            { return tls.ConnectionState{} }
func (*conn) close() error                                    { return errUnimplemented }
func (*conn) setDeadline(_ time.Time) error                   { return errUnimplemented }
func (*conn) setReadDeadline(_ time.Time) error               { return errUnimplemented }
func (*conn) setWriteDeadline(_ time.Time) error              { return errUnimplemented }
func (*conn) syscallConn() (syscall.RawConn, error)           { return nil, errUnimplemented }
