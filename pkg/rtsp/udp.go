package rtsp

import (
	"crypto/aes"
	"crypto/cipher"
)

// CreateUDPStream creates a simple AES-CTR stream for UDP encryption
// Uses same key as TCP tunnel but with zero IV (as UDP stream is stateless)
func CreateUDPStream(key []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize) // Zero IV for simplicity
	return cipher.NewCTR(block, iv), nil
}
