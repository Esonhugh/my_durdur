package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"

	"github.com/boratanrikulu/durdur/internal/generated"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	// inn.NativeEndian.PutUint32(ip, ipNum)
	return ip
}

func DropLog() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	e, err := newEBPFWithLink()
	if err != nil {
		return errors.New("ebpf init with Link failed: " + err.Error())
	}
	defer e.Close()

	rd, err := ringbuf.NewReader(e.Objects.EventReportArea)
	if err != nil {
		return errors.New("ebpf ringbuf reader init fail: " + err.Error())
	}
	defer rd.Close()
	log.Println("Starting Log....")
	LooplyReadRecords(rd)

	return nil
}

func LooplyReadRecords(rd *ringbuf.Reader) {
	var CurrentRecord generated.BpfMyEvent

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &CurrentRecord); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("Dropped Packect from %v to %v ", intToIP(CurrentRecord.Saddr), intToIP(CurrentRecord.Daddr))
	}
}
