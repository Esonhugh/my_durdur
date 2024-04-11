package ebpf

import (
	"errors"
	"net"

	log "github.com/sirupsen/logrus"
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
		Addr: ip2intL(ip),
		Port: port,
	}, uint64(0))
}

func (e *EBPF) DeleteFromIPAndPort(ip net.IP, port uint16) error {
	return e.XDPObjects.DropFromIpport.Delete(XDPIPPort{
		Addr: ip2intL(ip),
		Port: port,
	})
}

func (e *EBPF) AddToIPAndPort(ip net.IP, port uint16) error {
	return e.TCObjects.DropToIpport.Put(TCIPPort{
		Addr: ip2intL(ip),
		Port: port,
	}, uint64(0))
}

func (e *EBPF) DeleteToIPAndPort(ip net.IP, port uint16) error {
	return e.TCObjects.DropToIpport.Delete(TCIPPort{
		Addr: ip2intL(ip),
		Port: port,
	})
}

type (
	Direction string
	Operation string
)

const (
	Ingress Direction = "src"
	Egress  Direction = "dst"
)

const (
	Add Operation = "add"
	Del Operation = "del"
)

type AddDeleter interface {
	Put(key, value interface{}) error
	Delete(key interface{}) error
}

func (e *EBPF) MapOperation(op Operation, d Direction, ip net.IP, port uint16) error {
	log.Infof("MapOperation: %s %s %s %d", op, d, ip, port)
	var addDeleter AddDeleter
	var data any
	if d == Ingress {
		log.Debugf("Ingress!")
		ingress := e.XDPObjects
		if ip != nil && port != 0 {
			addDeleter = ingress.DropFromIpport
			data = XDPIPPort{
				Addr: ip2intL(ip),
				Port: port,
			}
		} else if ip != nil && port == 0 {
			addDeleter = ingress.DropFromAddrs
			data = ip.To4()
		} else if port != 0 && ip == nil {
			addDeleter = ingress.DropFromPorts
			data = port
		}
	} else if d == Egress {
		log.Debugf("Egress!")
		egress := e.TCObjects
		if ip != nil && port != 0 {
			addDeleter = egress.DropToIpport
			data = TCIPPort{
				Addr: ip2intL(ip),
				Port: port,
			}
		} else if ip != nil && port == 0 {
			addDeleter = egress.DropToAddrs
			data = ip.To4()
		} else if port != 0 && ip == nil {
			addDeleter = egress.DropToPorts
			data = port
		}
	}
	if addDeleter == nil {
		return errors.New("invalid direction, ip or port")
	}
	if op == Add {
		return addDeleter.Put(data, uint64(0))
	} else if op == Del {
		return addDeleter.Delete(data)
	}
	return errors.New("invalid operation")
}
