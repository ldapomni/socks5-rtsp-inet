package rtsp

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

const (
	// MagicByte is the start of an interleaved frame
	MagicByte = '$'
	// MaxFrameSize for pool allocation (4-byte header + max payload)
	MaxFrameSize = 4 + 65536
)

var frameBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, MaxFrameSize)
	},
}

// Frame represents an RTSP interleaved frame
type Frame struct {
	Channel int
	Payload []byte
}

// WriteFrame writes an interleaved frame to w using a pooled buffer
func WriteFrame(w io.Writer, channel int, payload []byte) error {
	buf := frameBufferPool.Get().([]byte)
	defer frameBufferPool.Put(buf)

	buf[0] = MagicByte
	buf[1] = byte(channel)
	binary.BigEndian.PutUint16(buf[2:], uint16(len(payload)))
	copy(buf[4:], payload)

	_, err := w.Write(buf[:4+len(payload)])
	return err
}

// ReadFrame reads a single frame from r
func ReadFrame(r *bufio.Reader) (*Frame, error) {
	// Peek to see if it's a magic byte, otherwise it might be a text response?
	// For now assume strictly interleaved or strict textual handling separation.
	// But in a tunnel, valid RTSP commands might come in.
	// Simple implementation: Expect '$' if we are in data mode.

	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if b != MagicByte {
		return nil, fmt.Errorf("expected magic byte '$', got '%c' (0x%x)", b, b)
	}

	header := make([]byte, 3) // Channel (1) + Length (2)
	_, err = io.ReadFull(r, header)
	if err != nil {
		return nil, err
	}

	channel := int(header[0])
	length := binary.BigEndian.Uint16(header[1:])

	payload := make([]byte, length)
	_, err = io.ReadFull(r, payload)
	if err != nil {
		return nil, err
	}

	return &Frame{
		Channel: channel,
		Payload: payload,
	}, nil
}
