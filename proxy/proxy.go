package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"ipv6-proxy/config"
)

type ProxyServer struct {
	Config *config.Config
}

func NewProxyServer(cfg *config.Config) *ProxyServer {
	return &ProxyServer{
		Config: cfg,
	}
}

func (p *ProxyServer) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[PROXY] Handling %s request for: %s %s from user: %v", 
			r.Method, r.URL.String(), r.Host, r.Context().Value("username"))
		log.Printf("[PROXY-DEBUG] Full request: Method=%s, URL=%s, Host=%s, Path=%s", 
			r.Method, r.URL.String(), r.Host, r.URL.Path)
		
		randomIP, err := generateRandomIPv6(p.Config.IPv6Range)
		if err != nil {
			http.Error(w, "Failed to generate IPv6 address", http.StatusInternalServerError)
			log.Println("[ERROR] Error generating random IPv6 address:", err)
			return
		}

		log.Printf("[PROXY] Generated IPv6 address: %s for request to %s", randomIP, r.URL)

		err = addIPToInterface(p.Config.Interface, randomIP.String())
		if err != nil {
			http.Error(w, "Failed to configure IPv6 address", http.StatusInternalServerError)
			log.Println("[ERROR] Error adding IP to interface:", err)
			return
		}

		defer removeIPFromInterface(p.Config.Interface, randomIP.String())

		time.Sleep(100 * time.Millisecond)

		if r.Method == http.MethodConnect {
			p.handleConnect(w, r, randomIP)
			return
		}

		p.handleHTTP(w, r, randomIP)
	}
}

func (p *ProxyServer) createSocketWithSourceIP(sourceIP net.IP, dstAddr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(dstAddr)
	if err != nil {
		if strings.Contains(dstAddr, ":") {
			host = dstAddr
			port = "80"
		} else {
			host = dstAddr
			port = "80"
		}
	}

	log.Printf("[SOCKET] Creating connection to %s:%s using source IP %s", host, port, sourceIP.String())

	portNum, _ := strconv.Atoi(port)
	if portNum == 0 {
		portNum = 80
	}
	
	if strings.Contains(host, ":") {
		log.Printf("[SOCKET] Host appears to be IPv6 address: %s", host)
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if ip != nil && ip.To4() == nil {
			log.Printf("[SOCKET] Using direct IPv6 address: %s", ip.String())
			laddr := &net.TCPAddr{IP: sourceIP, Port: 0}
			dstAddr := &net.TCPAddr{IP: ip, Port: portNum}
			
			conn, err := net.DialTCP("tcp6", laddr, dstAddr)
			if err != nil {
				log.Printf("[ERROR] Failed to connect using direct IPv6: %v", err)
			} else {
				log.Printf("[SOCKET] Direct IPv6 connection successful")
				return conn, nil
			}
		}
	}
	
	targetIP, err := LookupIPv6(host)
	if err != nil {
		log.Printf("[ERROR] Failed to resolve host %s to IPv6: %v", host, err)
		if errors.Is(err, ErrNoIPv6Address) {
			return nil, fmt.Errorf("no IPv6 address found for host %s - IPv4-only sites are not supported", host)
		}
		return nil, fmt.Errorf("failed to resolve host %s: %v", host, err)
	}
	
	log.Printf("[SOCKET] Will connect to %s using IPv6 address: %s", host, targetIP.String())

	dstTCPAddr := &net.TCPAddr{
		IP:   targetIP,
		Port: portNum,
	}

	laddr := &net.TCPAddr{IP: sourceIP, Port: 0}
	
	log.Printf("[SOCKET] Dialing from %s to %s:%d", sourceIP.String(), targetIP.String(), portNum)
	conn, err := net.DialTCP("tcp6", laddr, dstTCPAddr)
	if err != nil {
		log.Printf("[ERROR] Failed to connect: %v", err)
		return nil, fmt.Errorf("failed to connect to IPv6 target: %v", err)
	}

	log.Printf("[SOCKET] Established IPv6 connection from %s to %s", sourceIP.String(), targetIP.String())
	return conn, nil
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request, sourceIP net.IP) {
	host := r.RequestURI
	
	log.Printf("[CONNECT] Starting CONNECT handler with RequestURI: %s", host)
	
	hostport := host
	
	if strings.HasPrefix(hostport, "https://") {
		hostport = strings.TrimPrefix(hostport, "https://")
	} else if strings.HasPrefix(hostport, "http://") {
		hostport = strings.TrimPrefix(hostport, "http://")
	}
	
	if hostport == "" {
		if r.URL.Path != "" && r.URL.Path != "/" {
			hostport = r.URL.Path
			log.Printf("[CONNECT] Using URL.Path: %s", hostport)
		} else if r.Host != "" {
			hostport = r.Host
			log.Printf("[CONNECT] Using r.Host: %s", hostport)
		}
	}
	
	if hostport == "" {
		log.Printf("[ERROR] Could not determine host for CONNECT")
		http.Error(w, "No target host specified", http.StatusBadRequest)
		return
	}
	
	log.Printf("[CONNECT] Final host before port check: %s", hostport)
	
	if !strings.Contains(hostport, ":") {
		hostport = hostport + ":443"
		log.Printf("[CONNECT] Added default port: %s", hostport)
	}

	hostname, _, err := net.SplitHostPort(hostport)
	if err != nil {
		log.Printf("[ERROR] Invalid host:port format %s: %v", hostport, err)
		http.Error(w, "Invalid host:port format", http.StatusBadRequest)
		return
	}
	
	log.Printf("[DNS] Resolving hostname: %s", hostname)
	
	lookupIP, err := LookupIPv6(hostname)
	if err != nil {
		log.Printf("[ERROR] Failed to resolve %s: %v", hostname, err)
		http.Error(w, fmt.Sprintf("Failed to resolve host: %v", err), http.StatusBadGateway)
		return
	}
	
	log.Printf("[CONNECT] Resolved %s to IPv6: %s", hostname, lookupIP.String())

	targetConn, err := p.createSocketWithSourceIP(sourceIP, hostport)
	if err != nil {
		log.Printf("[ERROR] CONNECT to %s failed: %v", hostport, err)
		
		if errors.Is(err, ErrNoIPv6Address) {
			http.Error(w, "No IPv6 address found for host", http.StatusBadGateway)
		} else {
			http.Error(w, fmt.Sprintf("Failed to connect: %v", err), http.StatusBadGateway)
		}
		return
	}
	defer targetConn.Close()
	
	log.Printf("[CONNECT] Successfully connected to target: %s", hostport)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[ERROR] Hijacking not supported for client %s", r.RemoteAddr)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[ERROR] Hijack error for %s: %v", hostport, err)
		http.Error(w, fmt.Sprintf("Hijack error: %v", err), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("[ERROR] Error sending connection established to client: %v", err)
		return
	}

	log.Printf("[CONNECT] HTTPS connection established to %s", hostport)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		copied, err := io.Copy(targetConn, clientConn)
		if err != nil {
			log.Printf("[DEBUG] Error copying client -> target for %s: %v", hostport, err)
		} else {
			log.Printf("[DEBUG] Copied %d bytes from client -> target for %s", copied, hostport)
		}
		
		if tcpConn, ok := targetConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		copied, err := io.Copy(clientConn, targetConn)
		if err != nil {
			log.Printf("[DEBUG] Error copying target -> client for %s: %v", hostport, err)
		} else {
			log.Printf("[DEBUG] Copied %d bytes from target -> client for %s", copied, hostport)
		}
		
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
	log.Printf("[CONNECT] HTTPS connection to %s closed", hostport)
}

func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request, sourceIP net.IP) {
	targetURL := r.URL.String()
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + r.Host + targetURL
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid URL: %v", err), http.StatusBadRequest)
		return
	}

	host := parsedURL.Host
	if !strings.Contains(host, ":") {
		if parsedURL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	targetConn, err := p.createSocketWithSourceIP(sourceIP, host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to target: %v", err), http.StatusBadGateway)
		log.Printf("HTTP error connecting to %s: %v", host, err)
		return
	}
	defer targetConn.Close()

	var requestBuffer strings.Builder
	requestBuffer.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, parsedURL.RequestURI()))
	
	for key, values := range r.Header {
		if isHopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			requestBuffer.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}
	
	if r.Header.Get("Host") == "" {
		requestBuffer.WriteString(fmt.Sprintf("Host: %s\r\n", parsedURL.Host))
	}
	
	requestBuffer.WriteString("Connection: close\r\n\r\n")
	
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusInternalServerError)
			return
		}
		requestBuffer.Write(body)
	}
	
	_, err = targetConn.Write([]byte(requestBuffer.String()))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send request: %v", err), http.StatusInternalServerError)
		return
	}
	
	resp, err := http.ReadResponse(bufio.NewReader(targetConn), r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read response: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	
	w.WriteHeader(resp.StatusCode)
	
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error copying response body: %v", err)
	}
	
	log.Printf("HTTP request completed: %s %s -> %d", r.Method, targetURL, resp.StatusCode)
}

func isHopByHopHeader(header string) bool {
	hopByHopHeaders := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailers":            true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}
	return hopByHopHeaders[http.CanonicalHeaderKey(header)]
}

func DisableDAD(iface string) {
	exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.accept_dad=0", iface)).Run()
}

func GetDefaultInterface() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip.To4() == nil && ip.IsGlobalUnicast() {
				return iface.Name, nil
			}
		}
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name, nil
		}
	}

	return "", fmt.Errorf("no suitable network interface found")
}

func addIPToInterface(iface, ip string) error {
	cmd := exec.Command("ip", "-6", "addr", "add", ip+"/128", "dev", iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add IP: %s, output: %s", err, string(output))
	}
	return nil
}

func removeIPFromInterface(iface, ip string) error {
	cmd := exec.Command("ip", "-6", "addr", "del", ip+"/128", "dev", iface)
	_, _ = cmd.CombinedOutput()
	return nil
}

func generateRandomIPv6(cidr string) (net.IP, error) {
	return GenerateRandomIPv6(cidr)
}

type IPv6Generator interface {
	GenerateRandomIPv6(cidr string) (net.IP, error)
} 