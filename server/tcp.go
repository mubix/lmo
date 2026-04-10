package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	mrand "math/rand/v2"
	"net"
	"syscall"
	"time"
)

var connSem chan struct{}

// Pre-computed static responses (built once after flag parsing — avoids
// fmt.Sprintf on every connection in the hot path).
var (
	respHTTP     []byte
	respSSH      []byte
	respOverload = []byte("w00tw00t\n")
)

// buildResponses pre-computes byte slices for responses that don't change
// per connection. Must be called after flags are parsed.
func buildResponses() {
	body := "w00tw00t\n"
	respHTTP = []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/plain\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"X-Egress-Test: w00tw00t\r\n"+
			"X-Server: %s\r\n"+
			"\r\n%s",
		len(body), flagDomain, body))
	respSSH = []byte(fmt.Sprintf("SSH-2.0-w00tw00t_%s\r\n", flagDomain))
}

// SO_REUSEPORT is not exported by syscall on Linux. The constant value is 15.
const soReusePort = 15

// setReusePort enables SO_REUSEPORT on a listening socket so multiple
// goroutines can each have their own listener on the same port. The kernel
// load-balances accepted connections across them — this removes the single
// accept queue bottleneck and scales linearly with core count.
func setReusePort(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
	})
	if err != nil {
		return err
	}
	return sockErr
}

// listenTCP starts flagNumListeners parallel accept loops, each with its own
// SO_REUSEPORT socket. iptables DNATs all TCP (except SMTP and admin SSH) to
// the configured port; the kernel distributes new connections across loops.
func listenTCP(addr string) {
	connSem = make(chan struct{}, flagMaxConns)
	lc := net.ListenConfig{Control: setReusePort}

	log.Printf("tcp listener on %s (%d accept loops, max %d conns, %dms peek)",
		addr, flagNumListeners, flagMaxConns, flagPeekTimeout)

	for i := 0; i < flagNumListeners; i++ {
		go acceptLoop(lc, addr, i)
	}
}

func acceptLoop(lc net.ListenConfig, addr string, id int) {
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		log.Fatalf("tcp listen #%d on %s: %v", id, addr, err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		select {
		case connSem <- struct{}{}:
			go func() {
				defer func() { <-connSem }()
				handleTCP(conn)
			}()
		default:
			// At capacity — still return w00tw00t so the egress test passes
			conn.Write(respOverload)
			conn.Close()
		}
	}
}

func handleTCP(conn net.Conn) {
	defer conn.Close()

	// Short timeout for protocol detection. Clients that speak first
	// (HTTP, HTTPS, SSH) send within milliseconds. Clients that wait for
	// a server greeting (FTP, telnet, nc) hit this timeout and get a
	// multi-protocol 220 greeting.
	conn.SetReadDeadline(time.Now().Add(time.Duration(flagPeekTimeout) * time.Millisecond))

	peek := make([]byte, 4)
	n, err := io.ReadAtLeast(conn, peek, 1)
	if err != nil {
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		writeGreeting(conn)
		return
	}
	peek = peek[:n]
	conn.SetReadDeadline(time.Time{})

	switch {
	case peek[0] == 0x16:
		handleTLS(conn, peek)
	case matchHTTP(peek):
		handleHTTP(conn)
	case n >= 3 && peek[0] == 'S' && peek[1] == 'S' && peek[2] == 'H':
		handleSSH(conn)
	default:
		writeEcho(conn)
	}
}

func matchHTTP(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	switch string(b[:3]) {
	case "GET", "POS", "PUT", "DEL", "HEA", "OPT", "PAT", "CON", "TRA":
		return true
	}
	if len(b) >= 4 && string(b[:4]) == "HTTP" {
		return true
	}
	return false
}

// handleHTTP writes the pre-computed HTTP 200 response.
func handleHTTP(conn net.Conn) {
	cntHTTP.Add(1)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(respHTTP)
}

// handleTLS completes the TLS handshake using the wildcard cert and serves
// the pre-computed HTTP response over TLS.
func handleTLS(conn net.Conn, peeked []byte) {
	cfg := getTLSConfig()
	if cfg == nil {
		writeEcho(conn)
		return
	}
	cntTLS.Add(1)
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	tlsConn := tls.Server(&prefixConn{Conn: conn, prefix: peeked}, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	// Best-effort drain of the HTTP request before responding
	tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.ReadAll(io.LimitReader(tlsConn, 8192))

	tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	tlsConn.Write(respHTTP)
}

// handleSSH writes the pre-computed SSH version string and closes. No key
// exchange, no auth — nothing to brute force.
func handleSSH(conn net.Conn) {
	cntSSH.Add(1)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write(respSSH)

	// Politely read rest of client's version line, then close
	buf := make([]byte, 256)
	conn.Read(buf)
}

// listenSMTP handles port 25 directly (iptables RETURN bypasses the DNAT).
// Also uses SO_REUSEPORT for consistency, though SMTP traffic is low volume.
func listenSMTP(addr string) {
	lc := net.ListenConfig{Control: setReusePort}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		log.Fatalf("smtp listen %s: %v", addr, err)
	}
	log.Printf("smtp listener on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			cntSMTP.Add(1)
			c.SetDeadline(time.Now().Add(3 * time.Second))
			fmt.Fprintf(c, "220 %s ESMTP w00tw00t|SMTP|%s|%08x\r\n",
				flagDomain,
				time.Now().UTC().Format(time.RFC3339),
				mrand.Uint32())
		}(conn)
	}
}

// --- Dynamic catch-all responses (include timestamp + nonce for uniqueness) ---

// writeGreeting is sent to clients that don't speak first. The "220" prefix
// makes this a valid FTP/SMTP greeting while still being greppable as w00tw00t.
func writeGreeting(conn net.Conn) {
	cntEcho.Add(1)
	fmt.Fprintf(conn, "220 %s w00tw00t|%s|%08x\r\n",
		flagDomain,
		time.Now().UTC().Format(time.RFC3339),
		mrand.Uint32())
}

// writeEcho handles unknown protocols where the client did send data.
func writeEcho(conn net.Conn) {
	cntEcho.Add(1)
	fmt.Fprintf(conn, "w00tw00t|ECHO|%s|%s|%08x\n",
		flagDomain,
		time.Now().UTC().Format(time.RFC3339),
		mrand.Uint32())
}

// prefixConn replays peeked bytes before reading from the real connection.
// Used to hand a partially-read connection to the TLS library.
type prefixConn struct {
	net.Conn
	prefix []byte
	off    int
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(b, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(b)
}
