package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"rtsp-tunnel/pkg/logger"
	"rtsp-tunnel/pkg/pool"
	"rtsp-tunnel/pkg/rtsp"
	"rtsp-tunnel/pkg/socks"
	"rtsp-tunnel/pkg/tunnel"
	"sync"
	"time"

	"crypto/tls"
	"context"
	"github.com/quic-go/quic-go"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
)

var (
	tcpBufferSize = 32 * 1024
)

// Helper to tune TCP connection
func tuneConnection(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
		tcp.SetReadBuffer(tcpBufferSize)
		tcp.SetWriteBuffer(tcpBufferSize)
	}
}

func main() {
	port := flag.Int("port", 8554, "RTSP Server Port")
	udpPort := flag.Int("udp-port", 8555, "UDP Proxy Port")
	logFile := flag.String("logfile", "", "Path to log file")
	logLevel := flag.String("loglevel", "info", "Log level (debug, info, error)")
	tcpBuf := flag.Int("tcp-buffer", 32, "TCP buffer size in KB")
	flag.Parse()

	tcpBufferSize = *tcpBuf * 1024

	// Init Logger
	if err := logger.Init(*logFile, *logLevel); err != nil {
		log.Fatalf("Failed to init logger: %v", err)
	}

	// Start UDP Proxy (direct encrypted UDP - fallback if not blocked)
	go startUDPProxy(*udpPort)

	// Start QUIC Server
	go startQUICServer(*port)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		logger.Fatalf("Failed to listen on %d: %v", *port, err)
	}
	logger.Infof("RTSP Server listening on :%d (UDP proxy on :%d, UDP tunneling via RTSP)", *port, *udpPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Errorf("Accept error: %v", err)
			continue
		}
		tuneConnection(conn)
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// RTSP Handshake Loop
	var sessionID string

	for {
		req, err := rtsp.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				logger.Errorf("RTSP Read Error: %v", err)
			}
			return
		}

		logger.Debugf("RTSP Method: %s, URL: %s", req.Method, req.URL)

		switch req.Method {
		case "OPTIONS":
			// Reply with Public options
			fmt.Fprintf(conn, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nPublic: OPTIONS, SETUP, TEARDOWN, PLAY\r\n\r\n", req.Headers.Get("CSeq"))
		case "SETUP":
			// Generate Session ID
			sessionID = "12345678"
			// Reply with Session
			fmt.Fprintf(conn, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nSession: %s\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n", req.Headers.Get("CSeq"), sessionID)
		case "PLAY":
			// Reply OK and start tunnel
			fmt.Fprintf(conn, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nSession: %s\r\nRange: npt=0.000-\r\n\r\n", req.Headers.Get("CSeq"), sessionID)

			// Start Tunnel Mode
			startTunnel(conn, reader)
			return
		case "TEARDOWN":
			fmt.Fprintf(conn, "RTSP/1.0 200 OK\r\nCSeq: %s\r\n\r\n", req.Headers.Get("CSeq"))
			return
		default:
			// 405 Method Not Allowed
			fmt.Fprintf(conn, "RTSP/1.0 405 Method Not Allowed\r\nCSeq: %s\r\n\r\n", req.Headers.Get("CSeq"))
		}
	}
}

func startTunnel(clientConn net.Conn, reader *bufio.Reader) error {
	logger.Infof("Starting RTSP Tunnel for %s", clientConn.RemoteAddr())

	// Muxer
	var writeMu sync.Mutex
	muxer := tunnel.NewMuxer(func(id uint32, data []byte) error {
		// Callback receives Encrypted RTP Packet (from per-session logic)
		// Just wrap in RTSP Frame (Channel 1 for Downstream)

		writeMu.Lock()
		defer writeMu.Unlock()
		return rtsp.WriteFrame(clientConn, 1, data)
	})

	// Add Datagram support if clientConn is a QUIC wrapper
	if qw, ok := clientConn.(interface {
		GetQUICSession() quic.Connection
		GetDatagrams() <-chan []byte
	}); ok {
		sess := qw.GetQUICSession()
		muxer.SetDatagramWriter(func(id uint32, data []byte) error {
			return sess.SendDatagram(data)
		})

		// Start pulling datagrams from the wrapper and feeding them to muxer
		go func() {
			dgChan := qw.GetDatagrams()
			for data := range dgChan {
				if len(data) < 12 {
					continue
				}
				ssrc := binary.BigEndian.Uint32(data[8:])
				muxer.HandlePacket(ssrc, data)
			}
		}()
	}
	defer muxer.CloseAll()

	// Handle new TCP connections from Client
	muxer.SetOnConnectHandler(func(id uint32, addr string) {
		logger.Infof("TCP Proxy: [%d] -> %s", id, addr)

		// Upstream Crypto (Client -> Server)
		fromClientProc, err := rtsp.NewPacketProcessor(rtsp.DefaultEncryptionKey)
		if err != nil {
			logger.Errorf("Crypto error: %v", err)
			return
		}

		// Create AsyncConn to buffer incoming data while we Dial
		ac := tunnel.NewAsyncConn()

		// Wrap with DecryptWriter so Muxer writes (encrypted RTP) get decrypted before buffering
		wrappedAC := tunnel.NewDecryptWriter(ac, fromClientProc)
		muxer.Register(id, wrappedAC)

		go func() {
			targetConn, err := net.Dial("tcp", addr)
			if err != nil {
				logger.Errorf("Failed to dial target %s: %v", addr, err)
				muxer.SendClose(id)
				muxer.Unregister(id)
				return
			}
			tuneConnection(targetConn)

			// Flush buffer and set target
			if err := ac.SetTarget(targetConn); err != nil {
				logger.Errorf("Failed to set target: %v", err)
				muxer.SendClose(id)
				muxer.Unregister(id)
				return
			}

			// Downstream Crypto (Server -> Client)
			toClientProc, err := rtsp.NewPacketProcessor(rtsp.DefaultEncryptionKey)
			if err != nil {
				logger.Errorf("Crypto error: %v", err)
				muxer.SendClose(id)
				muxer.Unregister(id)
				return
			}

			// Forward Reverse: Target -> Client (Tunnel)
			buf := pool.Get()
			defer pool.Put(buf)
			encBuf := pool.Get()
			defer pool.Put(encBuf)

			for {
				readLimit := cap(buf) - rtsp.RTPHeaderSize
				n, err := targetConn.Read(buf[:readLimit])
				if err != nil {
					muxer.SendClose(id)
					muxer.Unregister(id)
					return
				}

				// Encrypt
				nEnc, err := toClientProc.ProcessUpstreamTo(buf[:n], encBuf, id)
				if err != nil {
					break
				}

				// Send
				if err := muxer.Send(id, encBuf[:nEnc]); err != nil {
					break
				}
			}
		}()
	})

	// Read Loop: Client -> Server
	for {
		frame, err := rtsp.ReadFrame(reader)
		if err != nil {
			return err
		}

		// Channel 0 is Upstream Data (Client -> Server)
		if frame.Channel == 0 {
			// SSRC check
			if len(frame.Payload) < 12 {
				continue
			}
			ssrc := binary.BigEndian.Uint32(frame.Payload[8:])

			// Check for UDP session (SSRC >= 0x80000000)
			if ssrc >= 0x80000000 {
				go handleUDPSession(ssrc, frame.Payload, muxer)
				continue
			}

			// TCP packet - handle via Muxer
			// Writes encrypted payload to wrappedAC, which decrypts and writes to AsyncConn
			muxer.HandlePacket(ssrc, frame.Payload)
		}
	}
}

// handleUDPSession handles a tunneled UDP session
func handleUDPSession(ssrc uint32, encryptedPayload []byte, muxer *tunnel.Muxer) {
	// Decrypt payload
	proc, err := rtsp.NewPacketProcessor(rtsp.DefaultEncryptionKey)
	if err != nil {
		logger.Errorf("UDP crypto error: %v", err)
		return
	}

	// Strip RTP header and decrypt
	if len(encryptedPayload) < 12 {
		return
	}

	// Decrypt (ProcessDownstream strips RTP header and decrypts)
	decrypted, err := proc.ProcessDownstream(encryptedPayload)
	if err != nil {
		logger.Errorf("UDP decrypt error: %v", err)
		return
	}

	// Parse SOCKS5 UDP header to get destination
	req, err := socks.ParseUDPRequest(decrypted)
	if err != nil {
		logger.Errorf("Failed to parse SOCKS5 UDP: %v", err)
		return
	}

	destAddr := fmt.Sprintf("%s:%d", req.DestAddr, req.DestPort)
	logger.Debugf("UDP Tunnel: [0x%X] -> %s (%d bytes)", ssrc, destAddr, len(req.Data))

	// Resolve destination
	udpDest, err := net.ResolveUDPAddr("udp", destAddr)
	if err != nil {
		logger.Errorf("Failed to resolve %s: %v", destAddr, err)
		return
	}

	// Create UDP connection to destination
	destConn, err := net.DialUDP("udp", nil, udpDest)
	if err != nil {
		logger.Errorf("Failed to dial %s: %v", destAddr, err)
		return
	}
	defer destConn.Close()

	// Send query
	_, err = destConn.Write(req.Data)
	if err != nil {
		logger.Errorf("Failed to write to %s: %v", destAddr, err)
		return
	}

	// Wait for response with timeout
	destConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := pool.Get()
	defer pool.Put(respBuf)

	respN, err := destConn.Read(respBuf[:cap(respBuf)-rtsp.RTPHeaderSize])
	if err != nil {
		logger.Debugf("No response from %s: %v", destAddr, err)
		return
	}

	// Encode SOCKS5 UDP reply
	reply, err := socks.EncodeUDPReply(req.DestAddr, req.DestPort, respBuf[:respN])
	if err != nil {
		logger.Errorf("Failed to encode UDP reply: %v", err)
		return
	}

	// Encrypt response
	respProc, err := rtsp.NewPacketProcessor(rtsp.DefaultEncryptionKey)
	if err != nil {
		logger.Errorf("Failed to create response crypto: %v", err)
		return
	}

	encResp := pool.Get()
	defer pool.Put(encResp)

	nEnc, err := respProc.ProcessUpstreamTo(reply, encResp, ssrc)
	if err != nil {
		logger.Errorf("Failed to encrypt response: %v", err)
		return
	}

	// Send back via muxer (will use Datagram if possible)
	if err := muxer.SendDatagram(ssrc, encResp[:nEnc]); err != nil {
		logger.Errorf("Failed to send UDP response: %v", err)
		return
	}

	logger.Debugf("UDP Tunnel: [0x%X] <- %s (%d bytes)", ssrc, destAddr, respN)
}

// startUDPProxy starts the direct encrypted UDP proxy (fallback if not blocked)
func startUDPProxy(port int) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.Fatalf("Failed to resolve UDP addr: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		logger.Fatalf("Failed to listen UDP: %v", err)
	}
	defer conn.Close()

	logger.Infof("Direct UDP Proxy listening on :%d", port)

	// Create encryption stream
	stream, err := rtsp.CreateUDPStream(rtsp.DefaultEncryptionKey)
	if err != nil {
		logger.Fatalf("Failed to create UDP crypto: %v", err)
	}

	// Session tracking: destination -> client_addr
	type udpSession struct {
		clientAddr *net.UDPAddr
		lastActive time.Time
	}
	sessions := make(map[string]*udpSession)
	var sessionsMu sync.RWMutex

	// Cleanup goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			sessionsMu.Lock()
			now := time.Now()
			for key, sess := range sessions {
				if now.Sub(sess.lastActive) > 2*time.Minute {
					delete(sessions, key)
					logger.Debugf("Direct UDP session expired: %s", key)
				}
			}
			sessionsMu.Unlock()
		}
	}()

	buf := make([]byte, 2048)
	decBuf := make([]byte, 2048)

	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logger.Errorf("UDP read error: %v", err)
			continue
		}

		// Decrypt
		stream.XORKeyStream(decBuf[:n], buf[:n])

		// Parse SOCKS5 UDP header
		req, err := socks.ParseUDPRequest(decBuf[:n])
		if err != nil {
			logger.Errorf("Failed to parse SOCKS5 UDP: %v", err)
			continue
		}

		destAddr := fmt.Sprintf("%s:%d", req.DestAddr, req.DestPort)
		logger.Debugf("Direct UDP: %s -> %s (%d bytes)", clientAddr, destAddr, len(req.Data))

		// Store session
		sessionsMu.Lock()
		sessions[destAddr] = &udpSession{
			clientAddr: clientAddr,
			lastActive: time.Now(),
		}
		sessionsMu.Unlock()

		// Forward to destination in goroutine
		go func(dest string, data []byte) {
			udpDest, err := net.ResolveUDPAddr("udp", dest)
			if err != nil {
				logger.Errorf("Failed to resolve %s: %v", dest, err)
				return
			}

			destConn, err := net.DialUDP("udp", nil, udpDest)
			if err != nil {
				logger.Errorf("Failed to dial %s: %v", dest, err)
				return
			}
			defer destConn.Close()

			// Send query
			_, err = destConn.Write(data)
			if err != nil {
				logger.Errorf("Failed to write to %s: %v", dest, err)
				return
			}

			// Wait for response
			destConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			respBuf := make([]byte, 2048)
			respN, err := destConn.Read(respBuf)
			if err != nil {
				logger.Debugf("No response from %s: %v", dest, err)
				return
			}

			// Encode SOCKS5 UDP reply
			reply, err := socks.EncodeUDPReply(req.DestAddr, req.DestPort, respBuf[:respN])
			if err != nil {
				logger.Errorf("Failed to encode UDP reply: %v", err)
				return
			}

			// Encrypt
			encReply := make([]byte, len(reply))
			stream.XORKeyStream(encReply, reply)

			// Send back to client
			sessionsMu.RLock()
			sess, ok := sessions[dest]
			sessionsMu.RUnlock()

			if ok {
				_, err = conn.WriteToUDP(encReply, sess.clientAddr)
				if err != nil {
					logger.Errorf("Failed to send response to client: %v", err)
				}
				logger.Debugf("Direct UDP: %s <- %s (%d bytes)", sess.clientAddr, dest, respN)
			}
		}(destAddr, req.Data)
	}
}

func startQUICServer(port int) {
	tlsConf := generateTLSConfig()
	conf := &quic.Config{
		KeepAlivePeriod: 10 * time.Second,
		EnableDatagrams: true,
		Allow0RTT:       true,
	}
	ln, err := quic.ListenAddr(fmt.Sprintf(":%d", port), tlsConf, conf)
	if err != nil {
		logger.Errorf("Failed to listen QUIC: %v", err)
		return
	}
	logger.Infof("QUIC Server listening on :%d", port)

	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			logger.Errorf("QUIC Accept error: %v", err)
			continue
		}
		go handleQUICConnection(conn)
	}
}

func handleQUICConnection(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func(s quic.Stream) {
			dgChan := make(chan []byte, 100)
			qConn := &quicConnWrapper{Stream: s, session: conn, dgChan: dgChan}
			
			// Start Datagram receive loop for this connection
			go func() {
				defer close(dgChan)
				for {
					data, err := conn.ReceiveDatagram(context.Background())
					if err != nil {
						return
					}
					select {
					case dgChan <- data:
					default:
						// Drop if buffer full
					}
				}
			}()

			handleConnection(qConn)
		}(stream)
	}
}

type quicConnWrapper struct {
	quic.Stream
	session quic.Connection
	dgChan  <-chan []byte
}

func (w *quicConnWrapper) GetQUICSession() quic.Connection { return w.session }
func (w *quicConnWrapper) GetDatagrams() <-chan []byte     { return w.dgChan }
func (w *quicConnWrapper) LocalAddr() net.Addr            { return w.session.LocalAddr() }
func (w *quicConnWrapper) RemoteAddr() net.Addr           { return w.session.RemoteAddr() }
func (w *quicConnWrapper) Close() error {
	w.Stream.CancelRead(0)
	return w.Stream.Close()
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"RTSP Tunnel"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"rtsp-quic"},
	}
}
