package ebpf

import (
	"net"
)

// Add puts given FROM IP to the Map.
func (e *EBPF) AddFromIP(ip net.IP) error {
	return e.XDPObjects.DropFromAddrs.Put(ip.To4(), uint64(0))
}

// DeleteToIP delete given FROM IP from the Map.
func (e *EBPF) DeleteFromIP(ip net.IP) error {
	return e.XDPObjects.DropFromAddrs.Delete(ip.To4())
}

func (e *EBPF) AddToIP(ip net.IP) error {
	return e.TCObjects.DropToAddrs.Put(ip.To4(), uint64(0))
}

func (e *EBPF) DeleteToIP(ip net.IP) error {
	return e.TCObjects.DropToAddrs.Delete(ip.To4())
}

func (e *EBPF) AddFromPort(port uint16) error {
	return e.XDPObjects.DropFromPorts.Put(port, uint64(0))
}

func (e *EBPF) DeleteFromPort(port uint16) error {
	return e.XDPObjects.DropFromPorts.Delete(port)
}

func (e *EBPF) AddToPort(port uint16) error {
	return e.TCObjects.DropToPorts.Put(port, uint64(0))
}

func (e *EBPF) DeleteToPort(port uint16) error {
	return e.TCObjects.DropToPorts.Delete(port)
}

func (e *EBPF) AddFromIPAndPort(ip net.IP, port uint16) error {
	return e.XDPObjects.DropFromIpport.Put(XDPIPPort{
		Addr: ip2int(ip),
		Port: port,
	}, uint64(0))
}

func (e *EBPF) DeleteFromIPAndPort(ip net.IP, port uint16) error {
	return e.XDPObjects.DropFromIpport.Delete(XDPIPPort{
		Addr: ip2int(ip),
		Port: port,
	})
}

func (e *EBPF) AddToIPAndPort(ip net.IP, port uint16) error {
	return e.TCObjects.DropToIpport.Put(TCIPPort{
		Addr: ip2int(ip),
		Port: port,
	}, uint64(0))
}

func (e *EBPF) DeleteToIPAndPort(ip net.IP, port uint16) error {
	return e.TCObjects.DropToIpport.Delete(TCIPPort{
		Addr: ip2int(ip),
		Port: port,
	})
}

func (e *EBPF) AddDNSQuery(q DNSQuery) error {
	return e.XDPObjects.DropDns.Put(q, uint64(0))
}

func (e *EBPF) DeleteDNSQuery(q DNSQuery) error {
	return e.XDPObjects.DropDns.Delete(q)
}
