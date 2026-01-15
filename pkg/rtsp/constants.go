package rtsp

// DefaultEncryptionKey is a 32-byte key for AES-256.
// In a real application, this should be negotiated or configured.
var DefaultEncryptionKey = []byte("0123456789abcdef0123456789abcdef")

const (
	// RTPHeaderSize is the size of the fixed RTP header
	RTPHeaderSize = 12
)
