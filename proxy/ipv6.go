package proxy

import (
	"crypto/rand"
	"errors"
	"log"
	"math/big"
	"net"
)

var (
	ErrNoIPv6Address = errors.New("no IPv6 address found for host")
)

func GenerateRandomIPv6(cidr string) (net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	prefixLen, _ := ipnet.Mask.Size()
	hostBits := 128 - prefixLen

	ipInt := big.NewInt(0)
	ipInt.SetBytes(ipnet.IP)

	maxRand := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	maxRand.Sub(maxRand, big.NewInt(1))

	randInt, err := rand.Int(rand.Reader, maxRand)
	if err != nil {
		source := rand.Reader
		n, err := rand.Int(source, maxRand)
		if err != nil {
			return nil, err
		}
		randInt = n
	}

	ipInt.Add(ipInt, randInt)

	ip := make(net.IP, 16)
	bytes := ipInt.Bytes()
	copy(ip[16-len(bytes):], bytes)

	return ip, nil
}

func LookupIPv6(host string) (net.IP, error) {
	log.Printf("[DNS] Starting IPv6 lookup for host: %s", host)
	
	ips, err := net.LookupIP(host)
	if err != nil {
		log.Printf("[DNS] Error looking up %s: %v", host, err)
		return nil, err
	}

	log.Printf("[DNS] Found %d IPs for %s", len(ips), host)
	
	for i, ip := range ips {
		isIPv6 := ip.To4() == nil
		log.Printf("[DNS] IP #%d: %s (IPv6: %t)", i+1, ip.String(), isIPv6)
	}

	for _, ip := range ips {
		if ip.To4() == nil {
			log.Printf("[DNS] Selected IPv6 address: %s", ip.String())
			return ip, nil
		}
	}

	log.Printf("[DNS] No IPv6 addresses found for %s", host)
	return nil, ErrNoIPv6Address
} 