package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"net"
	"time"
)

// udpSem caps the number of concurrent handleUDP goroutines, analogous to
// connSem for TCP. Shared across all read loops.
var udpSem chan struct{}

const udpMaxHandlers = 10000

// listenUDP spawns flagNumListeners parallel UDP read loops (each with
// SO_REUSEPORT). The kernel load-balances incoming datagrams across them.
func listenUDP(addr string) {
	udpSem = make(chan struct{}, udpMaxHandlers)
	log.Printf("udp listener on %s (%d read loops, max %d handlers)",
		addr, flagNumListeners, udpMaxHandlers)
	lc := net.ListenConfig{Control: setReusePort}
	for i := 0; i < flagNumListeners; i++ {
		go udpReadLoop(lc, addr, i)
	}
}

func udpReadLoop(lc net.ListenConfig, addr string, id int) {
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		log.Fatalf("udp listen #%d on %s: %v", id, addr, err)
	}
	conn := pc.(*net.UDPConn)
	defer conn.Close()

	buf := make([]byte, 2048)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		select {
		case udpSem <- struct{}{}:
			// Copy into its own slice for the goroutine
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			go func() {
				defer func() { <-udpSem }()
				handleUDP(conn, client, pkt)
			}()
		default:
			// At capacity — drop the datagram. Unlike TCP we do not emit
			// an overload response: UDP has no connection state to clean
			// up and sending anything back would be amplification.
		}
	}
}

func handleUDP(conn *net.UDPConn, client *net.UDPAddr, data []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("udp panic from %v: %v", client, r)
		}
	}()
	if resp, ok := buildDNSResponse(data); ok {
		cntDNS.Add(1)
		conn.WriteToUDP(resp, client)
		return
	}
	cntUDPRaw.Add(1)
	conn.WriteToUDP([]byte("w00tw00t\n"), client)
}

// buildDNSResponse constructs a valid DNS response if the packet looks like
// a DNS query. Returns the wire-format response and true, or nil and false.
func buildDNSResponse(q []byte) ([]byte, bool) {
	// Minimum DNS header is 12 bytes
	if len(q) < 12 {
		return nil, false
	}

	id := q[0:2]
	qdCount := binary.BigEndian.Uint16(q[4:6])
	if qdCount == 0 {
		return nil, false
	}

	// Parse question: labels terminated by 0x00, then 2-byte type + 2-byte class
	off := 12
	end := bytes.IndexByte(q[off:], 0x00)
	if end < 0 {
		return nil, false
	}
	end += off
	if len(q) < end+1+4 {
		return nil, false
	}

	question := q[12 : end+1+4]
	qtype := binary.BigEndian.Uint16(q[end+1 : end+3])

	// Refuse ANY queries (qtype 255) — they exist almost exclusively as an
	// amplification vector and have no legitimate egress-test use case.
	if qtype == 255 {
		return nil, false
	}

	// Build response header
	rd := q[2] & 0x01 // preserve Recursion Desired flag
	flags := []byte{0x81 | rd, 0x80}
	qcounts := append([]byte{}, q[4:6]...)

	answer := buildAnswer(qtype)

	return bytes.Join([][]byte{
		id, flags, qcounts,
		{0x00, 0x01}, // ANCOUNT = 1
		{0x00, 0x00}, // NSCOUNT = 0
		{0x00, 0x00}, // ARCOUNT = 0
		question,
		answer,
	}, nil), true
}

func buildAnswer(qtype uint16) []byte {
	const (
		typeA    = 1
		typeTXT  = 16
		typeAAAA = 28
		typeMX   = 15
		typeSOA  = 6
	)

	ptr := []byte{0xc0, 0x0c}   // name pointer to question
	cls := []byte{0x00, 0x01}   // IN class
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 60)

	switch qtype {
	case typeA:
		// Return a recognizable IP (doesn't matter which — egress test is the TXT)
		ip := net.ParseIP("8.8.8.8").To4()
		rdl := []byte{0x00, 0x04}
		return join(ptr, []byte{0x00, typeA}, cls, ttl, rdl, ip)

	case typeAAAA:
		ip6 := net.ParseIP("2001:4860:4860::8888").To16()
		rdl := []byte{0x00, 0x10}
		return join(ptr, []byte{0x00, typeAAAA}, cls, ttl, rdl, ip6)

	case typeMX:
		exchange := encodeDNSName("mail.w00tw00t." + flagDomain + ".")
		rdl := make([]byte, 2)
		binary.BigEndian.PutUint16(rdl, uint16(2+len(exchange)))
		return join(ptr, []byte{0x00, typeMX}, cls, ttl, rdl, []byte{0x00, 0x0a}, exchange)

	case typeSOA:
		mname := encodeDNSName("ns1.w00tw00t." + flagDomain + ".")
		rname := encodeDNSName("hostmaster.w00tw00t." + flagDomain + ".")
		tail := make([]byte, 20)
		binary.BigEndian.PutUint32(tail[0:4], uint32(time.Now().Unix()))
		binary.BigEndian.PutUint32(tail[4:8], 3600)
		binary.BigEndian.PutUint32(tail[8:12], 600)
		binary.BigEndian.PutUint32(tail[12:16], 86400)
		binary.BigEndian.PutUint32(tail[16:20], 300)
		rdata := join(mname, rname, tail)
		rdl := make([]byte, 2)
		binary.BigEndian.PutUint16(rdl, uint16(len(rdata)))
		return join(ptr, []byte{0x00, typeSOA}, cls, ttl, rdl, rdata)

	default:
		// TXT for everything else (including explicit TXT queries)
		// This is the primary verification method for DNS egress testing
		txt := []byte("w00tw00t|DNS|" + flagDomain)
		rdl := make([]byte, 2)
		binary.BigEndian.PutUint16(rdl, uint16(len(txt)+1))
		return join(ptr, []byte{0x00, typeTXT}, cls, ttl, rdl, []byte{byte(len(txt))}, txt)
	}
}

// encodeDNSName converts "example.com." to DNS wire format [7]example[3]com[0]
func encodeDNSName(name string) []byte {
	var out []byte
	for _, label := range bytes.Split([]byte(name), []byte(".")) {
		if len(label) == 0 {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0x00)
}

func join(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}
