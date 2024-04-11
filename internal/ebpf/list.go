package ebpf

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

func ListRules() error {
	e, err := newEBPFWithLink()
	if err != nil {
		return err
	}
	defer e.Close()

	records := e.ListMap()
	for _, record := range records {
		if record.IP == nil {
			record.IP = net.IPv4zero
		}
		var f string
		if record.D == Egress {
			record.D = "host -egress-> "
		} else {
			record.D = "world -ingress->"
		}

		if record.Port == 0 {
			f = fmt.Sprintf("%v %v:any hint-rule:%v", record.D, record.IP, record.Count)
		} else {
			f = fmt.Sprintf("%v %v:%v hint-rule:%v", record.D, record.IP, record.Port, record.Count)
		}
		log.Info(f)
	}
	return nil
}

type eBPFRecord struct {
	D     Direction
	IP    net.IP
	Port  uint16
	Count uint64
}

func (e *EBPF) ListMap() []eBPFRecord {
	var record []eBPFRecord

	// DropFromAddrs
	{
		mapper := e.XDPObjects.DropFromAddrs.Iterate()
		for {
			var key uint32
			var value uint64
			ok := mapper.Next(&key, &value)
			if !ok {
				break
			}
			record = append(record, eBPFRecord{D: Ingress, IP: int2ipL(key), Count: value})
		}
	}
	// DropFromPorts
	{
		mapper := e.XDPObjects.DropFromPorts.Iterate()
		for {
			var key uint16
			var value uint64
			ok := mapper.Next(&key, &value)
			if !ok {
				break
			}
			record = append(record, eBPFRecord{D: Ingress, Port: htons(key), Count: value})
		}
	}
	// DropFromIpport
	{
		mapper := e.XDPObjects.DropFromIpport.Iterate()
		for {
			var key XDPIPPort
			var value uint64
			ok := mapper.Next(&key, &value)
			if !ok {
				break
			}
			record = append(record, eBPFRecord{D: Ingress, IP: int2ip(key.Addr), Port: htons(key.Port), Count: value})
		}
	}
	// DropToAddrs
	{
		mapper := e.TCObjects.DropToAddrs.Iterate()
		for {
			var key uint32
			var value uint64
			ok := mapper.Next(&key, &value)
			if !ok {
				break
			}
			record = append(record, eBPFRecord{D: Egress, IP: int2ipL(key), Count: value})
		}
	}
	// DropToPorts
	{
		mapper := e.TCObjects.DropToPorts.Iterate()
		for {
			var key uint16
			var value uint64
			ok := mapper.Next(&key, &value)
			if !ok {
				break
			}
			record = append(record, eBPFRecord{D: Egress, Port: htons(key), Count: value})
		}
	}
	// DropToIpport
	{
		mapper := e.TCObjects.DropToIpport.Iterate()
		for {
			var key TCIPPort
			var value uint64
			ok := mapper.Next(&key, &value)
			if !ok {
				break
			}
			record = append(record, eBPFRecord{D: Egress, IP: int2ip(key.Addr), Port: htons(key.Port), Count: value})
		}
	}

	return record
}
