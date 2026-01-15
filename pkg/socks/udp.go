package socks

import (
	"encoding/binary"
	"fmt"
	"net"
)

// UDPRequest represents a SOCKS5 UDP request datagram
type UDPRequest struct {
	Frag     byte
	DestAddr string
	DestPort int
	Data     []byte
}

// ParseUDPRequest parses a SOCKS5 UDP request datagram
// Format: RSV(2) FRAG(1) ATYP(1) DST.ADDR(Var) DST.PORT(2) DATA(Var)
func ParseUDPRequest(packet []byte) (*UDPRequest, error) {
	if len(packet) < 10 {
		return nil, fmt.Errorf("packet too short")
	}

	// RSV must be 0x0000
	if packet[0] != 0 || packet[1] != 0 {
		return nil, fmt.Errorf("invalid RSV")
	}

	frag := packet[2]
	atyp := packet[3]

	offset := 4
	var destAddr string

	switch atyp {
	case AddrTypeIPv4:
		if len(packet) < offset+4 {
			return nil, fmt.Errorf("packet too short for IPv4")
		}
		destAddr = net.IP(packet[offset : offset+4]).String()
		offset += 4
	case AddrTypeDomain:
		if len(packet) < offset+1 {
			return nil, fmt.Errorf("packet too short for domain length")
		}
		domainLen := int(packet[offset])
		offset++
		if len(packet) < offset+domainLen {
			return nil, fmt.Errorf("packet too short for domain")
		}
		destAddr = string(packet[offset : offset+domainLen])
		offset += domainLen
	case AddrTypeIPv6:
		if len(packet) < offset+16 {
			return nil, fmt.Errorf("packet too short for IPv6")
		}
		destAddr = net.IP(packet[offset : offset+16]).String()
		offset += 16
	default:
		return nil, fmt.Errorf("unsupported address type: %d", atyp)
	}

	if len(packet) < offset+2 {
		return nil, fmt.Errorf("packet too short for port")
	}
	destPort := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2

	data := packet[offset:]

	return &UDPRequest{
		Frag:     frag,
		DestAddr: destAddr,
		DestPort: destPort,
		Data:     data,
	}, nil
}

// EncodeUDPReply encodes a SOCKS5 UDP reply datagram
// Format: RSV(2) FRAG(1) ATYP(1) DST.ADDR(Var) DST.PORT(2) DATA(Var)
func EncodeUDPReply(destAddr string, destPort int, data []byte) ([]byte, error) {
	// Try to parse as IP first
	ip := net.ParseIP(destAddr)

	var header []byte
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			header = make([]byte, 10+len(data))
			header[0] = 0 // RSV
			header[1] = 0 // RSV
			header[2] = 0 // FRAG
			header[3] = AddrTypeIPv4
			copy(header[4:8], ip4)
			binary.BigEndian.PutUint16(header[8:10], uint16(destPort))
			copy(header[10:], data)
		} else {
			// IPv6
			header = make([]byte, 22+len(data))
			header[0] = 0 // RSV
			header[1] = 0 // RSV
			header[2] = 0 // FRAG
			header[3] = AddrTypeIPv6
			copy(header[4:20], ip)
			binary.BigEndian.PutUint16(header[20:22], uint16(destPort))
			copy(header[22:], data)
		}
	} else {
		// Domain
		if len(destAddr) > 255 {
			return nil, fmt.Errorf("domain too long")
		}
		header = make([]byte, 7+len(destAddr)+len(data))
		header[0] = 0 // RSV
		header[1] = 0 // RSV
		header[2] = 0 // FRAG
		header[3] = AddrTypeDomain
		header[4] = byte(len(destAddr))
		copy(header[5:5+len(destAddr)], destAddr)
		binary.BigEndian.PutUint16(header[5+len(destAddr):7+len(destAddr)], uint16(destPort))
		copy(header[7+len(destAddr):], data)
	}

	return header, nil
}
