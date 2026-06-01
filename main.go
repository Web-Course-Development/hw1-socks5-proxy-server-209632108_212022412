package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

const (
	socksVersion   = 0x05
	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodAuthFail = 0xFF

	authVersion = 0x01

	cmdConnect = 0x01

	atypIPv4   = 0x01 // IPv4
	atypDomain = 0x03

	repSuccess    = 0x00 // success
	repServerFail = 0x01 // server failure
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// 1. read client greeting & negotiate auth

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		log.Printf("Failed to read greeting header: %v", err)
		return
	}

	if header[0] != socksVersion {
		log.Printf("Unsupported SOCKS version: %d", header[0])
		return
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)

	if _, err := io.ReadFull(conn, methods); err != nil {
		log.Printf("Failed to read methods: %v", err)
		return
	}

	authMethod := byte(methodAuthFail)
	requiresAuth := os.Getenv("PROXY_USER") != ""

	for _, m := range methods {
		if requiresAuth && m == methodUserPass {
			authMethod = methodUserPass
			break
		} else if !requiresAuth && m == methodNoAuth {
			authMethod = methodNoAuth
			break
		}
	}

	reply := []byte{socksVersion, authMethod}
	if _, err := conn.Write(reply); err != nil {
		log.Printf("Failed to write handshake reply: %v", err)
		return
	}

	if authMethod == methodAuthFail {
		return
	}

	// 2. perform sub-negotiation auth if required

	if authMethod == methodUserPass {
		if !authenticateUserPass(conn) {
			log.Printf("Authentication failed for client connection")
			return
		}
	}

	// 3. read connect request
	targetAddr, err := readConnectRequest(conn)
	if err != nil {
		log.Printf("Failed to read connect request: %v", err)
		return
	}
	log.Printf("Client wants to connect to destination: %s", targetAddr)

	// 4. Connect to target server via net.Dial
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to dial target server %s: %v", targetAddr, err)

		errReply := []byte{socksVersion, repServerFail, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
		conn.Write(errReply)
		return
	}
	defer target.Close()

	// 5. Send a SUCCESS reply back to the client
	successReply := []byte{socksVersion, repSuccess, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(successReply); err != nil {
		log.Printf("Failed to write success reply to client: %v", err)
		return
	}

	// 6. Relay data bidirectionally between client and target server
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, conn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, target)
	}()

	wg.Wait()
}

func authenticateUserPass(conn net.Conn) bool {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		log.Printf("Failed to read auth header: %v", err)
		return false
	}

	if header[0] != authVersion {
		log.Printf("Unsupported auth version: %d", header[0])
		return false
	}

	usernameLen := int(header[1])
	usernameBuf := make([]byte, usernameLen)

	if _, err := io.ReadFull(conn, usernameBuf); err != nil {
		log.Printf("Failed to read username: %v", err)
		return false
	}

	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		log.Printf("Failed to read password length: %v", err)
		return false
	}

	passLen := int(passLenBuf[0])
	passwordBuf := make([]byte, passLen)

	if _, err := io.ReadFull(conn, passwordBuf); err != nil {
		log.Printf("Failed to read password: %v", err)
		return false
	}

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(usernameBuf) == expectedUser && string(passwordBuf) == expectedPass {
		conn.Write([]byte{authVersion, 0x00})
		return true
	}

	conn.Write([]byte{authVersion, 0x01})
	return false
}

func readConnectRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("failed to read request header: %v", err)
	}

	if header[0] != socksVersion {
		return "", fmt.Errorf("unsupported request SOCKS version: %d", header[0])
	}

	if header[1] != cmdConnect {
		return "", fmt.Errorf("unsupported command code: %d", header[1])
	}

	atyp := header[3]
	var host string

	switch atyp {
	case atypIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", fmt.Errorf("failed to read IPv4 address: %v", err)
		}
		host = net.IP(ipBuf).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("failed to read domain length: %v", err)
		}
		domainLen := int(lenBuf[0])

		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", fmt.Errorf("failed to read domain name string: %v", err)
		}
		host = string(domainBuf)

	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("failed to read port bytes: %v", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	targetAddr := fmt.Sprintf("%s:%d", host, port)
	return targetAddr, nil
}