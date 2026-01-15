// UDP tunnel test utility
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"time"
)

func main() {
	var (
		socksHost = flag.String("host", "127.0.0.1", "SOCKS5 proxy host")
		socksPort = flag.Int("port", 1080, "SOCKS5 proxy port")
		socksUser = flag.String("user", "test", "SOCKS5 username")
		socksPass = flag.String("pass", "test2025", "SOCKS5 password")
	)
	flag.Parse()

	fmt.Println("=== SOCKS5 UDP Tunnel Test ===")

	addr := fmt.Sprintf("%s:%d", *socksHost, *socksPort)
	fmt.Printf("Connecting to SOCKS5 proxy at %s...\n", addr)

	// 1. Connect to SOCKS5 proxy
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("❌ Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	// 2. SOCKS5 handshake (try both NO_AUTH and USER/PASS)
	conn.Write([]byte{0x05, 0x02, 0x00, 0x02}) // VER=5, NMETHODS=2, METHODS: NO_AUTH, USER/PASS
	reply := make([]byte, 2)
	conn.Read(reply)

	if reply[1] == 0x02 {
		// Username/Password auth required
		fmt.Printf("Authentication required, using %s:%s credentials...\n", *socksUser, *socksPass)

		// Sub-negotiation: VER(1) ULEN UNAME PLEN PASSWD
		msg := make([]byte, 0, 3+len(*socksUser)+len(*socksPass))
		msg = append(msg, 0x01)
		msg = append(msg, byte(len(*socksUser)))
		msg = append(msg, []byte(*socksUser)...)
		msg = append(msg, byte(len(*socksPass)))
		msg = append(msg, []byte(*socksPass)...)

		conn.Write(msg)
		authReply := make([]byte, 2)
		conn.Read(authReply)
		if authReply[1] != 0x00 {
			fmt.Printf("❌ Authentication failed for user %s\n", *socksUser)
			return
		}
		fmt.Println("✓ Authenticated successfully")
	} else if reply[1] == 0x00 {
		fmt.Println("✓ SOCKS5 handshake successful (no auth)")
	} else {
		fmt.Printf("❌ Auth method not accepted: 0x%02X\n", reply[1])
		return
	}

	// 3. UDP ASSOCIATE request
	fmt.Println("Requesting UDP ASSOCIATE...")
	conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	assocReply := make([]byte, 10)
	n, _ := conn.Read(assocReply)
	if n < 10 || assocReply[1] != 0x00 {
		fmt.Printf("❌ UDP ASSOCIATE failed with code 0x%02X\n", assocReply[1])
		return
	}

	// Get UDP port from reply
	bndAddr := net.IP(assocReply[4:8]).String()
	bndPort := binary.BigEndian.Uint16(assocReply[8:10])
	fmt.Printf("✓ UDP ASSOCIATE success, BND.ADDR: %s, BND.PORT: %d\n", bndAddr, bndPort)

	// 4. Create UDP socket
	localUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		fmt.Printf("❌ Failed to create local UDP socket: %v\n", err)
		return
	}
	defer localUDP.Close()

	// 5. Build SOCKS5 UDP packet for DNS query to 8.8.8.8:53
	dnsQuery := []byte{
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Flags
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}

	socksUDP := []byte{
		0x00, 0x00, // RSV
		0x00, // FRAG
		0x01, // ATYP=IPv4
		8, 8, 8, 8,
		0x00, 0x35,
	}
	socksUDP = append(socksUDP, dnsQuery...)

	// 6. Send UDP packet to BND.ADDR:BND.PORT
	// Note: BND.ADDR might be "0.0.0.0", in which case we send to the proxy host
	targetIP := bndAddr
	if targetIP == "0.0.0.0" {
		targetIP = *socksHost
	}

	destAddr := &net.UDPAddr{IP: net.ParseIP(targetIP), Port: int(bndPort)}
	fmt.Printf("Sending DNS query (google.com) via SOCKS UDP endpoint %s:%d...\n", targetIP, bndPort)
	_, err = localUDP.WriteToUDP(socksUDP, destAddr)
	if err != nil {
		fmt.Printf("❌ Failed to send UDP packet: %v\n", err)
		return
	}

	// 7. Wait for response
	fmt.Println("Waiting for response (5s timeout)...")
	localUDP.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 2048)
	respN, _, err := localUDP.ReadFromUDP(respBuf)
	if err != nil {
		fmt.Printf("❌ No response: %v\n", err)
		return
	}

	fmt.Printf("✓ Received response! (%d bytes)\n", respN)
	fmt.Println("\n🎉 UDP TUNNEL SUCCESSFUL! 🎉")
}
