package tunnel

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"rtsp-tunnel/pkg/pool"
	"rtsp-tunnel/pkg/rtsp"
)

// UDPHandler handles UDP session responses
type UDPHandler func(data []byte) error

// Muxer manages multiple connections multiplexed over a single transport
type Muxer struct {
	mu          sync.RWMutex
	connections map[uint32]net.Conn
	udpHandlers map[uint32]UDPHandler              // UDP session handlers
	udpMu       sync.RWMutex                       // Separate lock for UDP
	onConnect      func(id uint32, addr string)       // Callback when peer requests connection
	writeTunnel    func(id uint32, data []byte) error // Function to write to RTSP/TCP Stream
	writeDatagram  func(id uint32, data []byte) error // Function to write QUIC Datagram
	closed         bool
}

// NewMuxer creates a new multiplexer
func NewMuxer(writer func(id uint32, data []byte) error) *Muxer {
	return &Muxer{
		connections: make(map[uint32]net.Conn),
		udpHandlers: make(map[uint32]UDPHandler),
		writeTunnel: writer,
	}
}

// SetDatagramWriter sets the callback for sending datagrams
func (m *Muxer) SetDatagramWriter(writer func(id uint32, data []byte) error) {
	m.writeDatagram = writer
}

// SetOnConnectHandler sets the handler for new incoming connection requests (control)
func (m *Muxer) SetOnConnectHandler(handler func(id uint32, addr string)) {
	m.onConnect = handler
}

// Register adds a connection to the muxer
func (m *Muxer) Register(id uint32, conn net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		conn.Close()
		return
	}
	m.connections[id] = conn
}

// Unregister removes a connection
func (m *Muxer) Unregister(id uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if conn, ok := m.connections[id]; ok {
		conn.Close()
		delete(m.connections, id)
	}
}

// Get returns a connection by ID
func (m *Muxer) Get(id uint32) (net.Conn, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	conn, ok := m.connections[id]
	return conn, ok
}

// RegisterUDP registers a UDP session handler
func (m *Muxer) RegisterUDP(id uint32, handler UDPHandler) {
	m.udpMu.Lock()
	defer m.udpMu.Unlock()
	m.udpHandlers[id] = handler
}

// UnregisterUDP removes a UDP session handler
func (m *Muxer) UnregisterUDP(id uint32) {
	m.udpMu.Lock()
	defer m.udpMu.Unlock()
	delete(m.udpHandlers, id)
}

// HandlePacket processes an incoming packet payload (decrypted)
func (m *Muxer) HandlePacket(id uint32, data []byte) error {
	// SSRC 0 is Control
	if id == ControlSSRC {
		var msg ControlMessage
		// Skip RTP Header (12 bytes)
		if len(data) < 12 {
			return nil
		}
		if err := json.Unmarshal(data[12:], &msg); err != nil {
			return fmt.Errorf("failed to unmarshal control msg: %v", err)
		}
		return m.handleControl(msg)
	}

	// Check for UDP session (SSRC >= 0x80000000)
	if id >= 0x80000000 {
		m.udpMu.RLock()
		handler, ok := m.udpHandlers[id]
		m.udpMu.RUnlock()

		if ok && handler != nil {
			return handler(data)
		}
		// No handler registered - ignore packet
		return nil
	}

	// TCP Data packet
	conn, ok := m.Get(id)
	if !ok {
		// If unknown ID, maybe send close?
		return nil
	}
	_, err := conn.Write(data)
	return err
}

func (m *Muxer) handleControl(msg ControlMessage) error {
	switch msg.Cmd {
	case "connect":
		if m.onConnect != nil {
			m.onConnect(msg.ID, msg.Addr)
		}
	case "close":
		m.Unregister(msg.ID)
	}
	return nil
}

// Send sends raw data via stream (RTP over TCP/QUIC Stream)
func (m *Muxer) Send(id uint32, data []byte) error {
	return m.writeTunnel(id, data)
}

// SendDatagram sends raw data via Datagram if available, otherwise fallback to stream
func (m *Muxer) SendDatagram(id uint32, data []byte) error {
	if m.writeDatagram != nil {
		return m.writeDatagram(id, data)
	}
	return m.writeTunnel(id, data)
}

// SendConnect sends a control message
func (m *Muxer) SendConnect(id uint32, addr string) error {
	b, _ := NewConnectMessage(id, addr)
	// Wrap in RTP Header so SSRC extraction works
	// SSRC 0 is Control
	pkt := make([]byte, 12+len(b))
	pkt[0] = 0x80
	binary.BigEndian.PutUint32(pkt[8:], ControlSSRC)
	copy(pkt[12:], b)

	return m.writeTunnel(ControlSSRC, pkt)
}

func (m *Muxer) SendClose(id uint32) error {
	b, _ := NewCloseMessage(id)
	pkt := make([]byte, 12+len(b))
	pkt[0] = 0x80
	binary.BigEndian.PutUint32(pkt[8:], ControlSSRC)
	copy(pkt[12:], b)
	return m.writeTunnel(ControlSSRC, pkt)
}

// ForwardConn reads from conn and sends to tunnel
func (m *Muxer) ForwardConn(id uint32, conn net.Conn) {
	defer m.SendClose(id)
	defer m.Unregister(id)

	buf := pool.Get()
	defer pool.Put(buf)

	lastDeadline := time.Now()
	conn.SetReadDeadline(lastDeadline.Add(5 * time.Minute))

	for {
		// Optimization: Update deadline only if significant time passed (e.g., every 1 minute)
		// to avoid syscall overhead on every packet.
		if time.Since(lastDeadline) > 1*time.Minute {
			lastDeadline = time.Now()
			conn.SetReadDeadline(lastDeadline.Add(5 * time.Minute))
		}

		readLimit := cap(buf) - rtsp.RTPHeaderSize
		n, err := conn.Read(buf[:readLimit])
		if err != nil {
			break
		}
		if err := m.writeTunnel(id, buf[:n]); err != nil {
			break
		}
	}
}

// CloseAll closes all connections
func (m *Muxer) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for _, conn := range m.connections {
		conn.Close()
	}
	m.connections = make(map[uint32]net.Conn)
}
