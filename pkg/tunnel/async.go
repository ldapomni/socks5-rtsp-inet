package tunnel

import (
	"bytes"
	"net"
	"sync"
	"time"
)

// AsyncConn acts as a placeholder for a connection that is being established.
// It buffers writes until SetTarget is called.
type AsyncConn struct {
	mu     sync.Mutex
	target net.Conn
	buffer *bytes.Buffer
	closed bool
}

// NewAsyncConn creates a new AsynConn
func NewAsyncConn() *AsyncConn {
	return &AsyncConn{
		buffer: new(bytes.Buffer),
	}
}

// SetTarget sets the underlying connection and flushes the buffer.
func (a *AsyncConn) SetTarget(conn net.Conn) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		conn.Close()
		return net.ErrClosed
	}

	a.target = conn

	// Flush buffer
	if a.buffer.Len() > 0 {
		_, err := conn.Write(a.buffer.Bytes())
		a.buffer = nil // release memory
		return err
	}
	a.buffer = nil
	return nil
}

// Write writes to the target or buffers if target is nil
func (a *AsyncConn) Write(b []byte) (n int, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return 0, net.ErrClosed
	}

	if a.target != nil {
		return a.target.Write(b)
	}

	return a.buffer.Write(b)
}

// Read is not implemented for this use case as we only buffer writes from client.
// Real reads happen from the target directly in the Forwarder logic.
func (a *AsyncConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

// Close closes the connection
func (a *AsyncConn) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	if a.target != nil {
		return a.target.Close()
	}
	return nil
}

// LocalAddr stub
func (a *AsyncConn) LocalAddr() net.Addr { return nil }

// RemoteAddr stub
func (a *AsyncConn) RemoteAddr() net.Addr { return nil }

// SetDeadline stub
func (a *AsyncConn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline stub
func (a *AsyncConn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline stub
func (a *AsyncConn) SetWriteDeadline(t time.Time) error { return nil }
