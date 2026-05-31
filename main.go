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

	authVersion    = 0x01

	cmdConnect     = 0x01 

	atypIPv4       = 0x01 // IPv4
	atypDomain     = 0x03 
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

	// 1. read client greeting & negotiate auth

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

	// 2. perform sub-negotiation auth if required 

	// if username/password auth was selected, we need to handle the login details next
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

	// 4. Connect to target server

	// establish a standard TCP outbound connection to the parsed destination
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to dial target server %s: %v", targetAddr, err)
		// if connecting fails, we will handle sending the error packet in Step 5, for now, we return to close the client connection safely.
		return
	}
	// closing outbound pipe 
	defer target.Close()


	// 5. Send success/error reply
	// 6. Relay data between client and target
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

   // helper function: parses the client's target destination details from the socket stream
   func readConnectRequest(conn net.Conn) (string, error) {
	// read the first 4 bytes of the request header
	// [Version (1B), Command (1B), Reserved (1B), Address Type (1B)]
	header := make([]byte, 4)
	if _, err := conn.Read(header); err != nil {
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

	// parse the target host based on Address Type (ATYP)
	switch atyp {
	case atypIPv4:
		// IPv4 address is exactly 4 bytes long
		ipBuf := make([]byte, 4)
		if _, err := conn.Read(ipBuf); err != nil {
			return "", fmt.Errorf("failed to read IPv4 address: %v", err)
		}
		host = net.IP(ipBuf).String()

	case atypDomain:
		// first byte indicates the length of the domain name string
		lenBuf := make([]byte, 1)
		if _, err := conn.Read(lenBuf); err != nil {
			return "", fmt.Errorf("failed to read domain length: %v", err)
		}
		domainLen := int(lenBuf[0])

		domainBuf := make([]byte, domainLen)
		if _, err := conn.Read(domainBuf); err != nil {
			return "", fmt.Errorf("failed to read domain name string: %v", err)
		}
		host = string(domainBuf)

	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}

	// read the final 2 bytes for the Port number
	portBuf := make([]byte, 2)
	if _, err := conn.Read(portBuf); err != nil {
		return "", fmt.Errorf("failed to read port bytes: %v", err)
	}
	// parse the 2 bytes as a Big-Endian uint16 value
	port := binary.BigEndian.Uint16(portBuf)

	// combine the host address string and port integer into a standard format: "host:port"
	targetAddr := fmt.Sprintf("%s:%d", host, port)
	return targetAddr, nil

}


