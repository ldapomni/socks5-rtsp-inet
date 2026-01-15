package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"rtsp-tunnel/pkg/logger"
	"rtsp-tunnel/pkg/pool"
	"rtsp-tunnel/pkg/rtsp"
	"rtsp-tunnel/pkg/socks"
	"rtsp-tunnel/pkg/tunnel"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/bcrypt"
)

var (
	serverAddr    = "127.0.0.1:8554"
	serverUDPAddr = "127.0.0.1:8555"
	udpManager    *UDPManager
	transportType = "tcp"
	tcpBufferSize = 32 * 1024
	stats         = NewStatsTracker()
	statsAddr     *string
	usersFile     *string
	usersMu       sync.RWMutex
)

type userAccount struct {
	password    string
	statsAccess bool
	isAdmin     bool
}

var users map[string]userAccount // user -> account

// Global session ticket for 0-RTT
var quicSessionTicket []byte
var sessionTicketMu sync.Mutex

// StatsTracker keeps track of real-time metrics
type StatsTracker struct {
	Pings         atomic.Uint64
	ActiveTunnels atomic.Int32

	// TCP Stats
	TCPSentBytes atomic.Uint64
	TCPRecvBytes atomic.Uint64

	// UDP Stats
	UDPSentBytes atomic.Uint64
	UDPRecvBytes atomic.Uint64
	UDPSentPkts  atomic.Uint64
	UDPRecvPkts  atomic.Uint64

	TotalRTT  atomic.Int64 // in microseconds
	RTTCount  atomic.Int64
	startTime time.Time
}

func NewStatsTracker() *StatsTracker {
	return &StatsTracker{startTime: time.Now()}
}

func (s *StatsTracker) Run() {
	// Start HTTP server for stats export
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
			// Get remote IP
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			isLocal := host == "127.0.0.1" || host == "::1" || host == "localhost"

			// Check auth if not local
			if !isLocal && users != nil {
				user, pass, ok := r.BasicAuth()
				if !ok {
					w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				usersMu.RLock()
				acc, found := users[user]
				usersMu.RUnlock()
				if !found || !checkPassword(pass, acc.password) || !acc.statsAccess {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"uptime":         time.Since(s.startTime).String(),
				"active_tunnels": s.ActiveTunnels.Load(),
				"tcp_sent":       s.TCPSentBytes.Load(),
				"tcp_recv":       s.TCPRecvBytes.Load(),
				"udp_sent":       s.UDPSentBytes.Load(),
				"udp_recv":       s.UDPRecvBytes.Load(),
				"udp_sent_pkts":  s.UDPSentPkts.Load(),
				"udp_recv_pkts":  s.UDPRecvPkts.Load(),
			})
		})

		mux.HandleFunc("POST /users", func(w http.ResponseWriter, r *http.Request) {
			// Get remote IP
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			isLocal := host == "127.0.0.1" || host == "::1" || host == "localhost"

			// Check auth if not local
			if !isLocal && users != nil {
				user, pass, ok := r.BasicAuth()
				if !ok {
					w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				usersMu.RLock()
				acc, found := users[user]
				usersMu.RUnlock()
				if !found || !checkPassword(pass, acc.password) || !acc.isAdmin {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}

			var newUser struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Stats    bool   `json:"stats"`
				Admin    bool   `json:"admin"`
				Update   bool   `json:"update"` // Optional hint
			}
			if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			if newUser.Username == "" || newUser.Password == "" {
				http.Error(w, "Username and password required", http.StatusBadRequest)
				return
			}

			hashed, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, "Error hashing password", http.StatusInternalServerError)
				return
			}

			usersMu.Lock()
			// If user exists, we can preserve permissions
			statsAccess := newUser.Stats
			isAdmin := newUser.Admin

			if existing, found := users[newUser.Username]; found && newUser.Update {
				// If it's an update-only request (e.g. from set-pass), keep existing flags
				statsAccess = existing.statsAccess
				isAdmin = existing.isAdmin
			}

			users[newUser.Username] = userAccount{
				password:    string(hashed),
				statsAccess: statsAccess,
				isAdmin:     isAdmin,
			}
			err = saveUsers(*usersFile)
			usersMu.Unlock()

			if err != nil {
				http.Error(w, "Error saving users", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
		})
		logger.Infof("Stats API listening on http://%s/stats (Auth active if users file loaded)", *statsAddr)
		if err := http.ListenAndServe(*statsAddr, mux); err != nil {
			logger.Errorf("Stats API failed: %v", err)
		}
	}()

	ticker := time.NewTicker(2 * time.Second)
	for range ticker.C {

		logger.Infof("[STATS] Tunnels: %d | TCP: ↑%s ↓%s | UDP: ↑%s ↓%s (%d pkts)",
			s.ActiveTunnels.Load(),
			formatBytes(s.TCPSentBytes.Load()), formatBytes(s.TCPRecvBytes.Load()),
			formatBytes(s.UDPSentBytes.Load()), formatBytes(s.UDPRecvBytes.Load()),
			s.UDPSentPkts.Load()+s.UDPRecvPkts.Load(),
		)
	}
}

func formatBytes(b uint64) string {
	if b < 1024 {
		return fmt.Sprintf("%dB", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	}
	return fmt.Sprintf("%.1fMB", float64(b)/(1024*1024))
}

// TunnelState represents a single RTSP tunnel
type TunnelState struct {
	conn  net.Conn
	muxer *tunnel.Muxer
	done  <-chan struct{}
}

// RTSPManager handles the lifecycle of multiple RTSP connections
type RTSPManager struct {
	mu           sync.RWMutex
	tunnels      []*TunnelState
	numTunnels   int
	reconnectDly time.Duration
	counter      uint64 // for round-robin
}

func NewRTSPManager(numTunnels int) *RTSPManager {
	if numTunnels < 1 {
		numTunnels = 1
	}
	return &RTSPManager{
		numTunnels:   numTunnels,
		reconnectDly: 3 * time.Second,
		tunnels:      make([]*TunnelState, numTunnels),
	}
}

// SelectTunnel returns a tunnel using round-robin selection
func (m *RTSPManager) SelectTunnel() *TunnelState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.tunnels) == 0 {
		return nil
	}

	idx := atomic.AddUint64(&m.counter, 1) % uint64(len(m.tunnels))
	return m.tunnels[idx]
}

func (m *RTSPManager) Start() {
	// Launch N tunnel managers
	for i := 0; i < m.numTunnels; i++ {
		tunnelID := i
		go m.manageTunnel(tunnelID)
	}
}

func (m *RTSPManager) manageTunnel(id int) {
	for {
		logger.Infof("Tunnel %d: Connecting to server (%s) via %s", id, serverAddr, transportType)
		var rtspConn net.Conn
		var muxer *tunnel.Muxer
		var done <-chan struct{}
		var err error

		if transportType == "quic" {
			rtspConn, muxer, done, err = connectQUIC()
		} else {
			rtspConn, muxer, done, err = connectRTSP()
		}

		if err != nil {
			logger.Errorf("Tunnel %d: Connection failed: %v. Retrying in %v...", id, err, m.reconnectDly)
			time.Sleep(m.reconnectDly)
			continue
		}

		logger.Infof("Tunnel %d: RTSP Tunnel Established", id)

		state := &TunnelState{
			conn:  rtspConn,
			muxer: muxer,
			done:  done,
		}

		m.mu.Lock()
		m.tunnels[id] = state
		m.mu.Unlock()
		stats.ActiveTunnels.Add(1)

		// Wait for connection termination
		<-done

		logger.Errorf("Tunnel %d: Connection lost. Cleaning up...", id)
		stats.ActiveTunnels.Add(-1)

		m.mu.Lock()
		m.tunnels[id] = nil
		if state.conn != nil {
			state.conn.Close()
		}
		m.mu.Unlock()

		time.Sleep(m.reconnectDly)
	}
}

// Helper to tune TCP connection
func tuneConnection(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
		tcp.SetReadBuffer(tcpBufferSize)
		tcp.SetWriteBuffer(tcpBufferSize)
	}
}

// UDPManager handles shared UDP listening and multiplexing
type UDPManager struct {
	mu          sync.RWMutex
	conn        *net.UDPConn
	manager     *RTSPManager
	sessions    map[string]*udpSessionState // ClientAddr -> session
	reverse     map[uint32]*udpSessionState // SSRC -> session
	ssrcCounter uint32
}

type udpSessionState struct {
	clientAddr *net.UDPAddr
	ssrc       uint32
	muxer      *tunnel.Muxer
	lastActive time.Time
}

func NewUDPManager(manager *RTSPManager, bindPort int) (*UDPManager, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", bindPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	m := &UDPManager{
		conn:        conn,
		manager:     manager,
		sessions:    make(map[string]*udpSessionState),
		reverse:     make(map[uint32]*udpSessionState),
		ssrcCounter: 0x80000000,
	}

	logger.Infof("Shared UDP Listener started on %s", conn.LocalAddr())
	go m.run()
	go m.cleanup()

	return m, nil
}

func (m *UDPManager) run() {
	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			logger.Errorf("Shared UDP Read error: %v", err)
			return
		}

		clientKey := clientAddr.String()

		m.mu.RLock()
		sess, ok := m.sessions[clientKey]
		m.mu.RUnlock()

		if !ok {
			// New session for this client address
			// For SOCKS5, the client must have already requested UDP ASSOCIATE.
			// Currently, we don't have a way to match clientAddr to a specific SOCKS session BEFORE the first packet.
			// SO we look for a SOCKS session that is "waiting" for an association from this IP?
			// Actually, typical implementation just creates a new session on the fly if it looks like SOCKS5 UDP.

			// Try to parse as SOCKS5 UDP
			req, err := socks.ParseUDPRequest(buf[:n])
			if err != nil {
				continue // Not a SOCKS5 UDP packet
			}

			// We need a muxer for this session. Use round-robin from RTSPManager.
			ts := m.manager.SelectTunnel()
			if ts == nil || ts.muxer == nil {
				logger.Errorf("No RTSP tunnel available for UDP")
				continue
			}

			ssrc := atomic.AddUint32(&m.ssrcCounter, 1)
			sess = &udpSessionState{
				clientAddr: clientAddr,
				ssrc:       ssrc,
				muxer:      ts.muxer,
				lastActive: time.Now(),
			}

			m.mu.Lock()
			m.sessions[clientKey] = sess
			m.reverse[ssrc] = sess
			m.mu.Unlock()

			// Register in Muxer for incoming tunnel responses
			ts.muxer.RegisterUDP(ssrc, func(data []byte) error {
				_, err := m.conn.WriteToUDP(data, clientAddr)
				if err == nil {
					m.mu.Lock()
					sess.lastActive = time.Now()
					m.mu.Unlock()
					stats.UDPRecvPkts.Add(1)
					stats.UDPRecvBytes.Add(uint64(len(data)))
				}
				return err
			})

			logger.Infof("New UDP-over-TCP session created: %s -> SSRC 0x%X (via tunnel)", clientKey, ssrc)
			logger.Debugf("UDP Initial Target: %s:%d", req.DestAddr, req.DestPort)
		}

		// Encrypt and send
		sess.lastActive = time.Now()

		upstreamProc, err := rtsp.NewPacketProcessor(rtsp.DefaultEncryptionKey)
		if err != nil {
			continue
		}

		encBuf := pool.Get()
		nEnc, err := upstreamProc.ProcessUpstreamTo(buf[:n], encBuf, sess.ssrc)
		if err == nil {
			// Use SendDatagram for UDP (will fallback to stream if not QUIC)
			if err := sess.muxer.SendDatagram(sess.ssrc, encBuf[:nEnc]); err == nil {
				stats.UDPSentPkts.Add(1)
				stats.UDPSentBytes.Add(uint64(nEnc))
			}
		}
		pool.Put(encBuf)
	}
}

func (m *UDPManager) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for key, sess := range m.sessions {
			if now.Sub(sess.lastActive) > 2*time.Minute {
				logger.Infof("Cleaning up idle UDP session: %s (SSRC 0x%X)", key, sess.ssrc)
				sess.muxer.UnregisterUDP(sess.ssrc)
				delete(m.sessions, key)
				delete(m.reverse, sess.ssrc)
			}
		}
		m.mu.Unlock()
	}
}

func main() {
	serverIP := flag.String("ip", "127.0.0.1", "RTSP Server IP")
	serverPort := flag.Int("port", 8554, "RTSP Server Port")
	serverUDPPort := flag.Int("udp-port", 8555, "Server UDP Port for encrypted proxy")
	socksPort := flag.Int("socks-port", 1080, "Local SOCKS5 Port")
	udpBindPort := flag.Int("udp-bind-port", 0, "Fixed local UDP port for SOCKS5 associations (0 = random)")
	numTunnels := flag.Int("tunnels", 4, "Number of parallel RTSP tunnels")
	usersFile = flag.String("users", "users.txt", "Path to user:pass file")
	logFile := flag.String("logfile", "", "Path to log file")
	logLevel := flag.String("loglevel", "info", "Log level (debug, info, error)")
	transport := flag.String("transport", "tcp", "Transport protocol (tcp, quic)")
	tcpBuf := flag.Int("tcp-buffer", 32, "TCP buffer size in KB")
	statsAddr = flag.String("stats-addr", "127.0.0.1:8080", "Address for stats API")
	flag.Parse()

	transportType = strings.ToLower(*transport)
	tcpBufferSize = *tcpBuf * 1024

	// Init Logger
	if err := logger.Init(*logFile, *logLevel); err != nil {
		log.Fatalf("Failed to init logger: %v", err)
	}

	serverAddr = fmt.Sprintf("%s:%d", *serverIP, *serverPort)
	serverUDPAddr = fmt.Sprintf("%s:%d", *serverIP, *serverUDPPort)

	if *usersFile != "" {
		var err error
		users, err = loadUsers(*usersFile)
		if err != nil {
			if os.IsNotExist(err) {
				logger.Infof("Users file %s not found, creating default admin:admin", *usersFile)
				users = make(map[string]userAccount)
				hashed, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
				users["admin"] = userAccount{password: string(hashed), statsAccess: true, isAdmin: true}
				saveUsers(*usersFile)
			} else {
				logger.Fatalf("Failed to load users: %v", err)
			}
		}
		logger.Infof("Loaded %d users", len(users))
	}

	// Start RTSP Manager with tunnel pool
	manager := NewRTSPManager(*numTunnels)
	logger.Infof("Starting %d parallel RTSP tunnels", *numTunnels)
	manager.Start()

	// Give tunnels time to establish
	time.Sleep(2 * time.Second)

	// Start Shared UDP Manager
	var err error
	udpManager, err = NewUDPManager(manager, *udpBindPort)
	if err != nil {
		logger.Fatalf("Failed to start UDP manager: %v", err)
	}

	// Start Stats
	go stats.Run()

	// Start SOCKS Listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *socksPort))
	if err != nil {
		logger.Fatalf("Failed to listen on %d: %v", *socksPort, err)
	}
	logger.Infof("SOCKS5 Proxy listening on :%d (TCP: %d tunnels, UDP: %s)", *socksPort, *numTunnels, udpManager.conn.LocalAddr())

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Errorf("Accept error: %v", err)
			continue
		}
		tuneConnection(conn)

		go handleSocksSession(conn, manager, rng)
	}
}

func loadUsers(path string) (map[string]userAccount, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	users := make(map[string]userAccount)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 2 {
			acc := userAccount{
				password:    parts[1],
				statsAccess: false,
				isAdmin:     false,
			}
			for i := 2; i < len(parts); i++ {
				if parts[i] == "stat" {
					acc.statsAccess = true
				} else if parts[i] == "admin" {
					acc.isAdmin = true
				}
			}
			users[parts[0]] = acc
		}
	}
	return users, scanner.Err()
}

func saveUsers(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	for user, acc := range users {
		line := fmt.Sprintf("%s:%s", user, acc.password)
		if acc.statsAccess {
			line += ":stat"
		}
		if acc.isAdmin {
			line += ":admin"
		}
		fmt.Fprintln(file, line)
	}
	return nil
}

func checkPassword(pass, hash string) bool {
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
		return err == nil
	}
	return pass == hash
}

// connectRTSP returns the conn, muxer, and a channel that closes when the connection dies
func connectRTSP() (net.Conn, *tunnel.Muxer, <-chan struct{}, error) {
	rtspConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, nil, nil, err
	}
	tuneConnection(rtspConn)
	rtspReader := bufio.NewReader(rtspConn)

	// RTSP Handshake
	cseq := 1
	// OPTIONS
	fmt.Fprintf(rtspConn, "OPTIONS rtsp://%s/rtsp RTSP/1.0\r\nCSeq: %d\r\n\r\n", serverAddr, cseq)
	cseq++
	if _, err := rtsp.ReadResponse(rtspReader); err != nil {
		rtspConn.Close()
		return nil, nil, nil, fmt.Errorf("OPTIONS failed: %v", err)
	}

	// SETUP (Multiplexed session)
	setupURL := fmt.Sprintf("rtsp://%s/rtsp", serverAddr)
	fmt.Fprintf(rtspConn, "SETUP %s RTSP/1.0\r\nCSeq: %d\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n", setupURL, cseq)
	cseq++
	resp, err := rtsp.ReadResponse(rtspReader)
	if err != nil || resp.StatusCode != 200 {
		rtspConn.Close()
		return nil, nil, nil, fmt.Errorf("SETUP failed: %v", err)
	}

	session := resp.Headers.Get("Session")

	// PLAY
	fmt.Fprintf(rtspConn, "PLAY %s RTSP/1.0\r\nCSeq: %d\r\nSession: %s\r\nRange: npt=0.000-\r\n\r\n", setupURL, cseq, session)
	cseq++
	if _, err := rtsp.ReadResponse(rtspReader); err != nil {
		rtspConn.Close()
		return nil, nil, nil, fmt.Errorf("PLAY failed: %v", err)
	}

	// Muxer
	var writeMu sync.Mutex
	muxer := tunnel.NewMuxer(func(id uint32, data []byte) error {
		// Passthrough: Data is already framed (RTP) and Encrypted (if SSRC != 0)
		// We just wrap it in RTSP Interleaved Frame (Channel 0)

		writeMu.Lock()
		defer writeMu.Unlock()
		return rtsp.WriteFrame(rtspConn, 0, data)
	})

	done := make(chan struct{})

	// Start Reading Loop
	go func() {
		defer close(done)
		defer rtspConn.Close()
		defer muxer.CloseAll()

		for {
			frame, err := rtsp.ReadFrame(rtspReader)
			if err != nil {
				if err != io.EOF {
					logger.Errorf("RTSP Read Error: %v", err)
				}
				return
			}

			if frame.Channel == 1 {
				// No global decryption.
				// SSRC extraction checks
				if len(frame.Payload) < 12 {
					continue
				}
				ssrc := binary.BigEndian.Uint32(frame.Payload[8:])

				// Handle Packet (Payload is still Encrypted RTP packet)
				// The Muxer's registered connection (DecryptWriter) will handle decryption.
				stats.TCPRecvBytes.Add(uint64(len(frame.Payload)))
				muxer.HandlePacket(ssrc, frame.Payload)
			}
		}
	}()

	return rtspConn, muxer, done, nil
}

func connectQUIC() (net.Conn, *tunnel.Muxer, <-chan struct{}, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"rtsp-quic"},
	}
	sessionTicketMu.Lock()
	if quicSessionTicket != nil {
		// Use saved ticket for 0-RTT?
		// Actually quic-go handles it if we provide a SessionCache
	}
	sessionTicketMu.Unlock()

	// Helper for session cache
	tlsConf.ClientSessionCache = tls.NewLRUClientSessionCache(10)

	conf := &quic.Config{
		KeepAlivePeriod: 10 * time.Second,
		EnableDatagrams: true,
		Allow0RTT:       true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, serverAddr, tlsConf, conf)
	if err != nil {
		return nil, nil, nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "failed to open stream")
		return nil, nil, nil, err
	}

	// Wrap QUIC stream to behave like net.Conn
	// quic.Stream implements net.Conn if we wrap it correctly or if the helper supports it.
	// Actually quic.Stream has Read/Write/Close and LocalAddr/RemoteAddr.
	// We might need a small wrapper if we need SetDeadline.

	// For simplicity, we can use the stream directly if tunnel functions expect net.Conn
	// but quic.Stream doesn't implement net.Conn directly (missing SetDeadline etc).
	// Let's use a simple wrapper.

	qConn := &quicConnWrapper{Stream: stream, session: conn}

	rtspReader := bufio.NewReader(qConn)

	// RTSP Handshake (same as TCP)
	cseq := 1
	fmt.Fprintf(qConn, "OPTIONS rtsp://%s/rtsp RTSP/1.0\r\nCSeq: %d\r\n\r\n", serverAddr, cseq)
	cseq++
	if _, err := rtsp.ReadResponse(rtspReader); err != nil {
		qConn.Close()
		return nil, nil, nil, fmt.Errorf("OPTIONS failed: %v", err)
	}

	setupURL := fmt.Sprintf("rtsp://%s/rtsp", serverAddr)
	fmt.Fprintf(qConn, "SETUP %s RTSP/1.0\r\nCSeq: %d\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n", setupURL, cseq)
	cseq++
	resp, err := rtsp.ReadResponse(rtspReader)
	if err != nil || resp.StatusCode != 200 {
		qConn.Close()
		return nil, nil, nil, fmt.Errorf("SETUP failed: %v", err)
	}

	session := resp.Headers.Get("Session")
	fmt.Fprintf(qConn, "PLAY %s RTSP/1.0\r\nCSeq: %d\r\nSession: %s\r\nRange: npt=0.000-\r\n\r\n", setupURL, cseq, session)
	cseq++
	if _, err := rtsp.ReadResponse(rtspReader); err != nil {
		qConn.Close()
		return nil, nil, nil, fmt.Errorf("PLAY failed: %v", err)
	}

	var writeMu sync.Mutex
	muxer := tunnel.NewMuxer(func(id uint32, data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return rtsp.WriteFrame(qConn, 0, data)
	})

	muxer.SetDatagramWriter(func(id uint32, data []byte) error {
		// id is SSRC, data is encrypted RTP packet
		// For QUIC Datagrams, we can send the whole RTP packet as one datagram
		return conn.SendDatagram(data)
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer qConn.Close()
		defer muxer.CloseAll()

		// Read Datagrams in parallel
		go func() {
			for {
				data, err := conn.ReceiveDatagram(context.Background())
				if err != nil {
					return
				}
				if len(data) < 12 {
					continue
				}
				stats.UDPRecvPkts.Add(1)
				stats.UDPRecvBytes.Add(uint64(len(data)))
				ssrc := binary.BigEndian.Uint32(data[8:])
				muxer.HandlePacket(ssrc, data)
			}
		}()

		for {
			frame, err := rtsp.ReadFrame(rtspReader)
			if err != nil {
				return
			}
			if frame.Channel == 1 {
				if len(frame.Payload) < 12 {
					continue
				}
				stats.TCPRecvBytes.Add(uint64(len(frame.Payload)))
				ssrc := binary.BigEndian.Uint32(frame.Payload[8:])
				muxer.HandlePacket(ssrc, frame.Payload)
			}
		}
	}()

	return qConn, muxer, done, nil
}

type quicConnWrapper struct {
	quic.Stream
	session quic.Connection
}

func (w *quicConnWrapper) LocalAddr() net.Addr  { return w.session.LocalAddr() }
func (w *quicConnWrapper) RemoteAddr() net.Addr { return w.session.RemoteAddr() }
func (w *quicConnWrapper) Close() error {
	w.Stream.CancelRead(0)
	return w.Stream.Close()
}

func handleSocksSession(conn net.Conn, manager *RTSPManager, rng *rand.Rand) {
	// Select a tunnel using round-robin
	ts := manager.SelectTunnel()
	if ts == nil || ts.muxer == nil {
		logger.Errorf("RTSP Tunnel not ready, rejecting SOCKS connection")
		conn.Close()
		return
	}

	muxer := ts.muxer

	// SOCKS Handshake
	var authenticator func(user, pass string) bool
	if len(users) > 0 {
		authenticator = func(u, p string) bool {
			usersMu.RLock()
			acc, ok := users[u]
			usersMu.RUnlock()
			res := ok && checkPassword(p, acc.password)
			if !res {
				logger.Errorf("SOCKS5 authentication failed for user: %s", u)
			}
			return res
		}
	}

	target, err := socks.Handshake(conn, authenticator)
	if err != nil {
		logger.Errorf("SOCKS handshake failed: %v", err)
		conn.Close()
		return
	}

	targetAddr := fmt.Sprintf("%s:%d", target.DestAddr, target.DestPort)
	logger.Infof("New request to %s (cmd=%d)", targetAddr, target.Cmd)

	// Handle UDP ASSOCIATE
	if target.Cmd == socks.CmdUDPAssociate {
		handleSharedUDPSession(conn)
		return
	}

	// Register with Muxer
	id := uint32(rng.Int31()) + 1

	// Setup Per-Session Decryption for Downstream (Server -> Client)
	downstreamProc, err := rtsp.NewPacketProcessor(rtsp.DefaultEncryptionKey)
	if err != nil {
		logger.Errorf("Failed to create downstream crypto: %v", err)
		conn.Close()
		return
	}

	// We wrap the conn so that when Muxer writes encrypted RTP packets to it,
	// they get decrypted and stripped before hitting the SOCKS socket.
	wrappedConn := tunnel.NewDecryptWriter(conn, downstreamProc)
	muxer.Register(id, wrappedConn)

	// Send Connect Message
	if err := muxer.SendConnect(id, targetAddr); err != nil {
		logger.Errorf("Failed to send connect: %v", err)
		muxer.Unregister(id) // closes conn
		return
	}

	// Send SOCKS Success
	if err := socks.SendReply(conn); err != nil {
		muxer.SendClose(id)
		muxer.Unregister(id)
		return
	}

	// Forward Data: SOCKS -> Muxer
	// per-session encryption to avoid global lock
	upstreamProc, err := rtsp.NewPacketProcessor(rtsp.DefaultEncryptionKey)
	if err != nil {
		logger.Errorf("Failed to create crypto: %v", err)
		return
	}

	buf := pool.Get()
	defer pool.Put(buf)

	encBuf := pool.Get()
	defer pool.Put(encBuf)

	for {
		// Read locally
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		readLimit := cap(buf) - rtsp.RTPHeaderSize
		n, err := conn.Read(buf[:readLimit])
		if err != nil {
			break
		}

		// Encrypt locally
		nEnc, err := upstreamProc.ProcessUpstreamTo(buf[:n], encBuf, id)
		if err != nil {
			logger.Errorf("Encrypt error: %v", err)
			break
		}

		// Send to Tunnel (Thread-safe Muxer Write)
		if err := muxer.Send(id, encBuf[:nEnc]); err != nil {
			break
		}
		stats.TCPSentBytes.Add(uint64(nEnc))
	}

	muxer.SendClose(id)
	muxer.Unregister(id)
}

func handleSharedUDPSession(tcpConn net.Conn) {
	localAddr := udpManager.conn.LocalAddr().(*net.UDPAddr)

	// Send SOCKS5 UDP ASSOCIATE reply with the SHARED port
	reply := make([]byte, 10)
	reply[0] = socks.Version5
	reply[1] = 0x00 // Success
	reply[2] = 0x00 // RSV
	reply[3] = socks.AddrTypeIPv4
	copy(reply[4:8], localAddr.IP.To4())
	binary.BigEndian.PutUint16(reply[8:10], uint16(localAddr.Port))

	if _, err := tcpConn.Write(reply); err != nil {
		logger.Errorf("Failed to send UDP ASSOCIATE reply: %v", err)
		return
	}

	// Keep TCP connection alive (SOCKS requirement)
	// If this connection closes, we SHOULD cleanup any sessions from this client,
	// but since we don't know which client IP/Port is associated with this TCP conn yet,
	// we rely on the 2-minute inactivity timeout in UDPManager.cleanup()
	buf := make([]byte, 1)
	tcpConn.Read(buf)
	tcpConn.Close()
}
