//go:build linux

package quicsys

import (
	"syscall"
	"unsafe"
)

// Constants and structures from the kernel QUIC UAPI header
// (modules/include/uapi/linux/quic.h in https://github.com/lxin/quic,
// verified against commit bf47121, 2026-08-21). Package quicsys is internal:
// the raw UAPI surface is not part of kquic's public API.

// Socket creation and option level.
const (
	IPPROTO_QUIC = 261
	SOL_QUIC     = 288
)

// quic_cmsg_type.
const (
	QUIC_STREAM_INFO    = 0
	QUIC_HANDSHAKE_INFO = 1
)

// Stream ID type masks.
const (
	QUIC_STREAM_TYPE_SERVER_MASK = 0x01
	QUIC_STREAM_TYPE_UNI_MASK    = 0x02
	QUIC_STREAM_TYPE_MASK        = 0x03
)

// quic_msg_flags: per-stream flags carried in quic_stream_info.stream_flags,
// plus extended msg_flags, all aliases of existing MSG_* bits.
const (
	MSG_QUIC_STREAM_NEW      = syscall.MSG_SYN
	MSG_QUIC_STREAM_FIN      = syscall.MSG_FIN
	MSG_QUIC_STREAM_UNI      = syscall.MSG_CONFIRM
	MSG_QUIC_STREAM_DONTWAIT = syscall.MSG_WAITFORONE
	MSG_QUIC_STREAM_SNDBLOCK = syscall.MSG_ERRQUEUE

	MSG_QUIC_DATAGRAM     = syscall.MSG_RST
	MSG_QUIC_NOTIFICATION = syscall.MSG_MORE
)

// quic_crypto_level.
const (
	QUIC_CRYPTO_APP       = 0
	QUIC_CRYPTO_INITIAL   = 1
	QUIC_CRYPTO_HANDSHAKE = 2
	QUIC_CRYPTO_EARLY     = 3
	QUIC_CRYPTO_MAX       = 4
)

// Socket options at SOL_QUIC.
const (
	QUIC_SOCKOPT_EVENT                = 0
	QUIC_SOCKOPT_STREAM_OPEN          = 1
	QUIC_SOCKOPT_STREAM_RESET         = 2
	QUIC_SOCKOPT_STREAM_STOP_SENDING  = 3
	QUIC_SOCKOPT_CONNECTION_ID        = 4
	QUIC_SOCKOPT_CONNECTION_CLOSE     = 5
	QUIC_SOCKOPT_CONNECTION_MIGRATION = 6
	QUIC_SOCKOPT_KEY_UPDATE           = 7
	QUIC_SOCKOPT_TRANSPORT_PARAM      = 8
	QUIC_SOCKOPT_CONFIG               = 9
	QUIC_SOCKOPT_TOKEN                = 10
	QUIC_SOCKOPT_ALPN                 = 11
	QUIC_SOCKOPT_SESSION_TICKET       = 12
	QUIC_SOCKOPT_CRYPTO_SECRET        = 13
	QUIC_SOCKOPT_TRANSPORT_PARAM_EXT  = 14
)

// QUIC versions for Config.Version.
const (
	QUIC_VERSION_V1 = 0x1
	QUIC_VERSION_V2 = 0x6b3343cf
)

// quic_cong_algo.
const (
	QUIC_CONG_ALG_RENO  = 0
	QUIC_CONG_ALG_CUBIC = 1
)

// TLS_CIPHER_* values from linux/tls.h used in CryptoSecret.Type,
// covering the TLS 1.3 suites crypto/tls implements.
const (
	TLS_CIPHER_AES_GCM_128       = 51
	TLS_CIPHER_AES_GCM_256       = 52
	TLS_CIPHER_AES_CCM_128       = 53
	TLS_CIPHER_CHACHA20_POLY1305 = 54
)

const QUIC_CRYPTO_SECRET_BUFFER_SIZE = 48

// HandshakeInfo is struct quic_handshake_info: the QUIC_HANDSHAKE_INFO
// cmsg payload carrying the crypto level of handshake data.
type HandshakeInfo struct {
	CryptoLevel uint8
}

// StreamInfo is struct quic_stream_info: the QUIC_STREAM_INFO cmsg
// payload carrying per-message stream metadata.
type StreamInfo struct {
	StreamID    int64
	StreamFlags uint32
	_           [4]byte
}

// CryptoSecret is struct quic_crypto_secret for
// QUIC_SOCKOPT_CRYPTO_SECRET.
type CryptoSecret struct {
	Send   uint8
	Level  uint8
	_      uint16
	Type   uint32
	Secret [QUIC_CRYPTO_SECRET_BUFFER_SIZE]byte
}

// TransportParam is struct quic_transport_param for
// QUIC_SOCKOPT_TRANSPORT_PARAM.
type TransportParam struct {
	Remote                   uint8
	DisableActiveMigration   uint8
	GreaseQUICBit            uint8
	StatelessReset           uint8
	Disable1RTTEncryption    uint8
	DisableCompatibleVersion uint8
	ActiveConnectionIDLimit  uint8
	AckDelayExponent         uint8
	MaxDatagramFrameSize     uint16
	MaxUDPPayloadSize        uint16
	MaxIdleTimeout           uint32
	MaxAckDelay              uint32
	MaxStreamsBidi           uint16
	MaxStreamsUni            uint16
	MaxData                  uint64
	MaxStreamDataBidiLocal   uint64
	MaxStreamDataBidiRemote  uint64
	MaxStreamDataUni         uint64
}

// Config is struct quic_config for QUIC_SOCKOPT_CONFIG.
type Config struct {
	Version                uint32
	PLPMTUDProbeInterval   uint32
	InitialSmoothedRTT     uint32
	PayloadCipherType      uint32
	CongestionControlAlgo  uint8
	ValidatePeerAddress    uint8
	StreamDataNodelay      uint8
	ReceiveSessionTicket   uint8
	CertificateRequest     uint8
	_                      [3]byte
	KeepaliveProbeInterval uint32
}

// Compile-time assertions that the Go structs match the C ABI sizes: each
// pair of array lengths is negative unless sizeof matches exactly.
var (
	_ [unsafe.Sizeof(HandshakeInfo{}) - 1]byte
	_ [1 - unsafe.Sizeof(HandshakeInfo{})]byte
	_ [unsafe.Sizeof(StreamInfo{}) - 16]byte
	_ [16 - unsafe.Sizeof(StreamInfo{})]byte
	_ [unsafe.Sizeof(CryptoSecret{}) - 56]byte
	_ [56 - unsafe.Sizeof(CryptoSecret{})]byte
	_ [unsafe.Sizeof(TransportParam{}) - 56]byte
	_ [56 - unsafe.Sizeof(TransportParam{})]byte
	_ [unsafe.Sizeof(Config{}) - 28]byte
	_ [28 - unsafe.Sizeof(Config{})]byte
)
