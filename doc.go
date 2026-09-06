// Package kquic provides access to Linux kernel QUIC sockets (IPPROTO_QUIC,
// https://github.com/lxin/quic): the kernel owns the QUIC transport while the
// TLS 1.3 handshake is driven in userspace by crypto/tls.
//
// This package is highly experimental and its API is unstable. The kernel
// QUIC module is out-of-tree and its UAPI may change.
package kquic
