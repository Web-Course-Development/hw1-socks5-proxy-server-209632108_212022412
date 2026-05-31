package main

import (
	"flag"
	"fmt"
	"log"
	"net"
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
	// 1. Read client greeting and negotiate authentication method

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

	// we send a 2-byte reply back to the client: [Version, SelectedMethod]
	reply := []byte{socksVersion, methodNoAuth}
	if _, err := conn.Write(reply); err != nil {
		log.Printf("Failed to write handshake reply: %v", err)
		return
	}

	// 2. Perform authentication if required (when PROXY_USER env var is set)
	// 3. Read CONNECT request
	// 4. Connect to target server
	// 5. Send success/error reply
	// 6. Relay data between client and target
}
