// letmeout — All-in-one egress filter testing server
//
// Single binary that replaces sslh + nginx/apache + custom Go services.
// Listens on TCP (all ports via iptables DNAT), SMTP (port 25), and UDP (all ports).
// Does its own protocol detection and responds with "w00tw00t" in every protocol.
//
// No external dependencies — stdlib only.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	flagDomain       string
	flagIP           string
	flagCert         string
	flagKey          string
	flagTCPPort      string
	flagSMTPPort     string
	flagUDPPort      string
	flagMaxConns     int
	flagPeekTimeout  int
	flagNumListeners int
)

// TLS certificate — reloaded on SIGHUP
var (
	tlsMu  sync.RWMutex
	tlsCfg *tls.Config
)

// Per-protocol connection counters, reset every stats interval
var (
	cntHTTP   atomic.Int64
	cntTLS    atomic.Int64
	cntSSH    atomic.Int64
	cntSMTP   atomic.Int64
	cntEcho   atomic.Int64
	cntDNS    atomic.Int64
	cntUDPRaw atomic.Int64
)

func main() {
	flag.StringVar(&flagDomain, "domain", env("DOMAIN", "letmeoutofyour.net"), "domain name for banners and certs")
	flag.StringVar(&flagIP, "ip", env("LISTEN_IP", "0.0.0.0"), "IP to bind listeners on")
	flag.StringVar(&flagCert, "cert", env("TLS_CERT", ""), "path to TLS fullchain.pem")
	flag.StringVar(&flagKey, "key", env("TLS_KEY", ""), "path to TLS privkey.pem")
	flag.StringVar(&flagTCPPort, "tcp-port", env("TCP_PORT", "80"), "main TCP listener port (iptables DNAT target)")
	flag.StringVar(&flagSMTPPort, "smtp-port", env("SMTP_PORT", "25"), "SMTP listener port (iptables RETURN)")
	flag.StringVar(&flagUDPPort, "udp-port", env("UDP_PORT", "5353"), "UDP listener port (iptables DNAT target)")
	flag.IntVar(&flagMaxConns, "max-conns", 200000, "max concurrent TCP connections")
	flag.IntVar(&flagPeekTimeout, "peek-ms", 300, "ms to wait for client data before sending server-first greeting")
	flag.IntVar(&flagNumListeners, "listeners", runtime.NumCPU(), "number of parallel TCP accept loops (SO_REUSEPORT)")
	flag.Parse()

	// Pre-compute static responses so the hot path is allocation-free
	buildResponses()

	loadTLSCert()

	go listenTCP(flagIP + ":" + flagTCPPort)
	go listenSMTP(flagIP + ":" + flagSMTPPort)
	go listenUDP(flagIP + ":" + flagUDPPort)
	go statsLoop()

	log.Printf("letmeout started — domain=%s ip=%s tcp=:%s smtp=:%s udp=:%s",
		flagDomain, flagIP, flagTCPPort, flagSMTPPort, flagUDPPort)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for s := range sig {
		if s == syscall.SIGHUP {
			log.Print("SIGHUP — reloading TLS certificate")
			loadTLSCert()
			continue
		}
		log.Printf("%v — shutting down", s)
		os.Exit(0)
	}
}

func loadTLSCert() {
	if flagCert == "" || flagKey == "" {
		log.Print("no TLS cert configured — HTTPS disabled")
		return
	}
	cert, err := tls.LoadX509KeyPair(flagCert, flagKey)
	if err != nil {
		log.Printf("WARNING: TLS cert load failed: %v", err)
		return
	}
	tlsMu.Lock()
	tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsMu.Unlock()
	log.Printf("TLS certificate loaded from %s", flagCert)
}

func getTLSConfig() *tls.Config {
	tlsMu.RLock()
	defer tlsMu.RUnlock()
	return tlsCfg
}

func statsLoop() {
	for range time.Tick(5 * time.Minute) {
		log.Printf("stats [5m] http=%d tls=%d ssh=%d smtp=%d echo=%d dns=%d udp=%d",
			cntHTTP.Swap(0), cntTLS.Swap(0), cntSSH.Swap(0),
			cntSMTP.Swap(0), cntEcho.Swap(0), cntDNS.Swap(0), cntUDPRaw.Swap(0))
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
