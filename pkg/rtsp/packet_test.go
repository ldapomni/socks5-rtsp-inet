package rtsp

import (
	"bytes"
	"testing"
)

func TestPacketProcessorRoundTrip(t *testing.T) {
	key := DefaultEncryptionKey

	// Create Upstream (Encrypt) and Downstream (Decrypt) processors
	// Note: They must handle the same stream logic.
	// As per implementation, ProcessUpstream and ProcessDownstream use identical XOR keystream if initialized same way.
	encryptProc, err := NewPacketProcessor(key)
	if err != nil {
		t.Fatalf("Failed to create encrypt processor: %v", err)
	}

	decryptProc, err := NewPacketProcessor(key)
	if err != nil {
		t.Fatalf("Failed to create decrypt processor: %v", err)
	}

	// Test Data
	originalData := []byte("Hello World, this is a secret message!")

	// 1. Encrypt (Upstream)
	packet, err := encryptProc.ProcessUpstream(originalData, 0)
	if err != nil {
		t.Fatalf("ProcessUpstream failed: %v", err)
	}

	// 2. Verify RTP Header
	if len(packet) != len(originalData)+RTPHeaderSize {
		t.Errorf("Expected length %d, got %d", len(originalData)+RTPHeaderSize, len(packet))
	}
	if packet[0] != 0x80 {
		t.Errorf("Expected V=2 (0x80), got 0x%x", packet[0])
	}
	if packet[1] != 0x60 {
		t.Errorf("Expected PT=96 (0x60), got 0x%x", packet[1])
	}

	// 3. Verify Payload is Encrypted (not equal to original)
	payload := packet[RTPHeaderSize:]
	if bytes.Equal(payload, originalData) {
		t.Error("Payload matches original data! Encryption failed or key is zero?")
	}

	// 4. Decrypt (Downstream)
	decrypted, err := decryptProc.ProcessDownstream(packet)
	if err != nil {
		t.Fatalf("ProcessDownstream failed: %v", err)
	}

	// 5. Verify Integrity
	if !bytes.Equal(decrypted, originalData) {
		t.Errorf("Decrypted data mismatch.\nExpected: %s\nGot:      %s", originalData, decrypted)
	}
}

func TestEncryptedPacketLooksLikeMedia(t *testing.T) {
	// Simple check that it doesn't look like HTTP or SOCKS
	proc, _ := NewPacketProcessor(DefaultEncryptionKey)
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	packet, _ := proc.ProcessUpstream(data, 0)

	// Packet should start with 0x80 0x60
	if packet[0] == 'G' && packet[1] == 'E' {
		t.Error("Packet starts with 'GE', leaking plaintext!")
	}
}
