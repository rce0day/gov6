package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"ipv6-proxy/api"
	"ipv6-proxy/auth"
	"ipv6-proxy/config"
	"ipv6-proxy/db"
	"ipv6-proxy/proxy"
)

var cfg *config.Config
var authenticator *auth.Authenticator

func connectHandler(w http.ResponseWriter, r *http.Request) {
	target := r.RequestURI
	if !strings.Contains(target, ":") {
		target = target + ":443"
	}
	
	randomIP, err := proxy.GenerateRandomIPv6(cfg.IPv6Range)
	if err != nil {
		http.Error(w, "Failed to generate IPv6 address", http.StatusInternalServerError)
		log.Printf("Error generating IPv6: %v", err)
		return
	}
	
	err = proxy.AddIPToInterface(cfg.Interface, randomIP.String())
	if err != nil {
		http.Error(w, "Failed to configure IPv6 address", http.StatusInternalServerError)
		log.Printf("Error adding IP to interface: %v", err)
		return
	}
	
	defer proxy.RemoveIPFromInterface(cfg.Interface, randomIP.String())
	
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		http.Error(w, "Invalid target address", http.StatusBadRequest)
		return
	}
	
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}
	
	ips, err := net.LookupIP(host)
	if err != nil {
		http.Error(w, "DNS resolution failed", http.StatusBadGateway)
		return
	}
	
	var targetIP net.IP
	for _, ip := range ips {
		if ip.To4() == nil {
			targetIP = ip
			break
		}
	}
	
	if targetIP == nil {
		http.Error(w, "No IPv6 address found for target", http.StatusBadGateway)
		return
	}
	
	srcAddr := &net.TCPAddr{
		IP:   randomIP,
		Port: 0,
	}
	
	dstAddr := &net.TCPAddr{
		IP:   targetIP,
		Port: port,
	}
	
	targetConn, err := net.DialTCP("tcp6", srcAddr, dstAddr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Connection failed: %v", err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	
	hijacker, canHijack := w.(http.Hijacker)
	if !canHijack {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()
	
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}
	
	var wg sync.WaitGroup
	wg.Add(2)
	
	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		targetConn.CloseWrite()
	}()
	
	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()
	
	wg.Wait()
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	proxy.NewProxyServer(cfg).Handler()(w, r)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/manage" {
		api.NewUserAPI(nil, authenticator).Handler()(w, r)
		return
	}
	
	_, authenticated := authenticator.Authenticate(r)
	if !authenticated {
		w.Header().Set("Proxy-Authenticate", `Basic realm="IPv6 Proxy"`)
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	
	if r.Method == http.MethodConnect {
		connectHandler(w, r)
	} else {
		httpHandler(w, r)
	}
}

func main() {
	log.SetFlags(log.LstdFlags)
	log.Println("Starting IPv6 proxy server...")

	cfg = config.LoadConfig()

	var err error
	if cfg.Interface == "" {
		cfg.Interface, err = proxy.GetDefaultInterface()
		if err != nil {
			log.Fatal("Error finding default interface:", err)
		}
	}

	log.Printf("Network interface: %s", cfg.Interface)
	log.Printf("IPv6 range: %s", cfg.IPv6Range)

	proxy.DisableDAD(cfg.Interface)

	database, err := db.NewDB(cfg)
	if err != nil {
		log.Fatal("Error initializing database:", err)
	}
	defer database.Close()

	authenticator = auth.NewAuthenticator(database)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      http.HandlerFunc(mainHandler),
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		log.Println("Shutting down server...")
		server.Close()
	}()

	log.Printf("Proxy server listening on :%s", cfg.Port)
	log.Fatal(server.ListenAndServe())
} 