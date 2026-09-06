# kquic [![Test Status](https://github.com/mdlayher/kquic/workflows/Test/badge.svg)](https://github.com/mdlayher/kquic/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/mdlayher/kquic.svg)](https://pkg.go.dev/github.com/mdlayher/kquic)

Package `kquic` provides access to Linux kernel QUIC sockets
([lxin/quic](https://github.com/lxin/quic), `IPPROTO_QUIC`): the kernel owns
the QUIC transport data path while the TLS 1.3 handshake is driven in
userspace by `crypto/tls`. MIT Licensed.

**This package is highly experimental and its API is unstable.** The kernel
QUIC module is out-of-tree and its UAPI may change.
