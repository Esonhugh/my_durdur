package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"github.com/boratanrikulu/durdur/internal/generated"
	"github.com/cilium/ebpf/ringbuf"
)

func DropLog() error {
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

	LooplyReadRecords(rd)

	return nil
}

var FromOrTo [2]string = [2]string{"to", "from"}

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
		if CurrentRecord.Direction == 0 || CurrentRecord.Direction == 1 {
			log.Printf("Dropped Packect %v %v ", FromOrTo[CurrentRecord.Direction], CurrentRecord.Addr)
		} else {
			log.Printf("Fail Read")
		}
	}
}
