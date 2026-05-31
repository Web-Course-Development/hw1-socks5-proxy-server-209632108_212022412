package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

const (
	socksVersion   = 0x05
	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodAuthFail = 0xFF

	authVersion    = 0x01 // byte for username/password sub-negotiation is 1
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

	// TODO: Implement SOCKS5 protocol

	// create a small slice to hold the first 2 bytes from the client
	header := make([]byte, 2)
	
	// read exactly 2 bytes from the network connection
	if _, err := conn.Read(header); err != nil {
		log.Printf("Failed to read greeting header: %v", err)
		return
	}

	// check if the first byte matches SOCKS version 5
	if header[0] != socksVersion {
		log.Printf("Unsupported SOCKS version: %d", header[0])
		return
	}

	// the second byte tells us how many authentication methods follow
	numMethods := int(header[1])
	methods := make([]byte, numMethods)

	// read the remaining method bytes from the network connection
	if _, err := conn.Read(methods); err != nil {
		log.Printf("Failed to read methods: %v", err)
		return
	}

    // determine which authentication method we require
	authMethod := byte(methodNoAuth)
	if os.Getenv("PROXY_USER") != "" {
		authMethod = methodUserPass
	}

	// send a 2-byte reply back to the client: [Version, SelectedMethod]
	reply := []byte{socksVersion, authMethod}
	if _, err := conn.Write(reply); err != nil {
		log.Printf("Failed to write handshake reply: %v", err)
		return
	}

	// if username/password auth was selected, we need to handle the login details next
	if authMethod == methodUserPass {
		if !authenticateUserPass(conn) {
			log.Printf("Authentication failed for client connection")
			return
		}
	}

   // helper function: reads the login packet from the client and validates credentials
   func authenticateUserPass(conn net.Conn) bool {
	// read the sub-negotiation header 
	header := make([]byte, 2)
	if _, err := conn.Read(header); err != nil {
		log.Printf("Failed to read auth header: %v", err)
		return false
	}

	// check if the auth sub-negotiation version is 0x01
	if header[0] != authVersion {
		log.Printf("Unsupported auth version: %d", header[0])
		return false
	}

	usernameLen := int(header[1])
	usernameBuf := make([]byte, usernameLen)
	
	// read the actual username characters
	if _, err := conn.Read(usernameBuf); err != nil {
		log.Printf("Failed to read username: %v", err)
		return false
	}

	// read the password length (1 byte)
	passLenBuf := make([]byte, 1)
	if _, err := conn.Read(passLenBuf); err != nil {
		log.Printf("Failed to read password length: %v", err)
		return false
	}

	passLen := int(passLenBuf[0])
	passwordBuf := make([]byte, passLen)

	// read the actual password characters
	if _, err := conn.Read(passwordBuf); err != nil {
		log.Printf("Failed to read password: %v", err)
		return false
	}

	// compare with our server environment variables
	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(usernameBuf) == expectedUser && string(passwordBuf) == expectedPass {
		// if we reached here that means we successed therefore reply with status 0x00
		conn.Write([]byte{authVersion, 0x00})
		return true
	}

	// if we reached here that means we failed therefore reply with status 0x01
	conn.Write([]byte{authVersion, 0x01})
	return false
}

	// 3. Read CONNECT request
	// 4. Connect to target server
	// 5. Send success/error reply
	// 6. Relay data between client and target
}
