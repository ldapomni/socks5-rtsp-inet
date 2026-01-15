package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	Version5 = 0x05

	MethodNoAuth   = 0x00
	MethodUserPass = 0x02

	CmdConnect      = 0x01
	CmdUDPAssociate = 0x03

	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04
)

// Request represents a SOCKS5 request
type Request struct {
	Cmd      byte
	DestAddr string
	DestPort int
}

// Handshake performs the SOCKS5 handshake on a connection
// authFunc: optional callback for username/password authentication.
// If nil, allows no-authentication.
func Handshake(conn net.Conn, authFunc func(user, pass string) bool) (*Request, error) {
	// 1. Negotiation
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] != Version5 {
		return nil, fmt.Errorf("unsupported socks version: %d", header[0])
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, err
	}

	// Determine method to use
	selectedMethod := byte(0xFF) // No Acceptable Methods

	if authFunc == nil {
		// Accept No Auth if user didn't request auth
		for _, m := range methods {
			if m == MethodNoAuth {
				selectedMethod = MethodNoAuth
				break
			}
		}
	} else {
		// Prefer User/Pass if configured
		for _, m := range methods {
			if m == MethodUserPass {
				selectedMethod = MethodUserPass
				break
			}
		}
	}

	if selectedMethod == 0xFF {
		conn.Write([]byte{Version5, 0xFF})
		return nil, fmt.Errorf("no acceptable authentication methods")
	}

	// Tell client selected method
	if _, err := conn.Write([]byte{Version5, selectedMethod}); err != nil {
		return nil, err
	}

	// 1.5 Authentication Sub-negotiation
	if selectedMethod == MethodUserPass {
		if err := performUserPassAuth(conn, authFunc); err != nil {
			return nil, err
		}
	}

	// 2. Request
	// Format: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(Var) DST.PORT(2)
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	if buf[0] != Version5 {
		return nil, fmt.Errorf("bad version in request")
	}

	cmd := buf[1]
	if cmd != CmdConnect && cmd != CmdUDPAssociate {
		return nil, fmt.Errorf("unsupported command: %d", cmd)
	}

	var destAddr string
	switch buf[3] {
	case AddrTypeIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return nil, err
		}
		destAddr = net.IP(ipBuf).String()
	case AddrTypeDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return nil, err
		}
		destAddr = string(domainBuf)
	case AddrTypeIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return nil, err
		}
		destAddr = net.IP(ipBuf).String()
	default:
		return nil, fmt.Errorf("unsupported address type: %d", buf[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	destPort := int(binary.BigEndian.Uint16(portBuf))

	return &Request{
		Cmd:      cmd,
		DestAddr: destAddr,
		DestPort: destPort,
	}, nil
}

// performUserPassAuth handles RFC 1929
func performUserPassAuth(conn net.Conn, authFunc func(user, pass string) bool) error {
	// Request: VER(1) ULEN(1) UNAME(VAR) PLEN(1) PASSWD(VAR)
	// VER should be 0x01 for sub-negotiation

	verUlen := make([]byte, 2)
	if _, err := io.ReadFull(conn, verUlen); err != nil {
		return err
	}

	if verUlen[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", verUlen[0])
	}

	ulen := int(verUlen[1])
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}

	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return err
	}

	plen := int(plenBuf[0])
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}

	success := authFunc(string(uname), string(passwd))

	// Response: VER(1) STATUS(1)
	status := byte(0x00) // Success
	if !success {
		status = 0x01 // Fail
	}

	conn.Write([]byte{0x01, status})

	if !success {
		return fmt.Errorf("authentication failed")
	}

	return nil
}

// SendReply sends a SOCKS5 reply indicating success or failure
// For simplicity, we just send success (0x00) and a dummy bind address
func SendReply(conn net.Conn) error {
	// VER(5) REP(0=Success) RSV(0) ATYP(1=IPv4) BND.ADDR(0) BND.PORT(0)
	// BND.ADDR is 4 bytes of 0
	resp := []byte{Version5, 0x00, 0x00, AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(resp)
	return err
}
