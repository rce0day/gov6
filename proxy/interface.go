package proxy

func AddIPToInterface(iface, ip string) error {
	return addIPToInterface(iface, ip)
}

func RemoveIPFromInterface(iface, ip string) error {
	return removeIPFromInterface(iface, ip)
} 