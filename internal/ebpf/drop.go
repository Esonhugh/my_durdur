package ebpf

import "net"

func DropV2(direction Direction, ip net.IP, port uint16) error {
	e, err := newEBPFWithLink()
	if err != nil {
		return err
	}
	defer e.Close()

	return e.MapOperation(Add, direction, ip, port)
}
