package ebpf

import (
	"net"
)

// Add puts given TO IP to the Map.
func (e *EBPF) AddToIP(ip net.IP) error {
	panic("not implemented")
}

// Add puts given FROM IP to the Map.
func (e *EBPF) AddFromIP(ip net.IP) error {
	return e.XDPObjects.DropFromAddrs.Put(ip.To4(), uint64(0))
}

// DeleteToIP deletes given TO IP from the Map.
func (e *EBPF) DeleteToIP(ip net.IP) error {
	panic("not implemented")
}

// DeleteToIP delete given FROM IP from the Map.
func (e *EBPF) DeleteFromIP(ip net.IP) error {
	return e.XDPObjects.DropFromAddrs.Delete(ip.To4())
}
