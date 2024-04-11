package ebpf

import (
	"errors"
	"net"

	log "github.com/sirupsen/logrus"
)

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
	port = htons(port)
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
