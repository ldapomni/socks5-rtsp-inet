package tunnel

import (
	"net"
	"rtsp-tunnel/pkg/pool"
	"rtsp-tunnel/pkg/rtsp"
)

// DecryptWriter wraps a net.Conn and decrypts all written data before passing to underlying conn.
// It assumes the data written to it is a full RTP packet (Header + EncPayload).
type DecryptWriter struct {
	net.Conn
	proc *rtsp.PacketProcessor
}

func NewDecryptWriter(c net.Conn, proc *rtsp.PacketProcessor) *DecryptWriter {
	return &DecryptWriter{
		Conn: c,
		proc: proc,
	}
}

func (d *DecryptWriter) Write(b []byte) (int, error) {
	// b is RTP Packet: Header(12) + EncPayload

	// Use pooled buffer for decryption
	decBuf := pool.Get()
	defer pool.Put(decBuf)

	nDec, err := d.proc.ProcessDownstreamTo(b, decBuf)
	if err != nil {
		// Log error? But we satisfy io.Writer interface
		// Just drop?
		return len(b), nil // Pretend we wrote it
	}

	// Write decrypted payload to real connection (SOCKS)
	_, err = d.Conn.Write(decBuf[:nDec])
	return len(b), err
}
