package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/boratanrikulu/durdur/internal/generated"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

func DropLogV2() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	e, err := newEBPFWithLink()
	if err != nil {
		return errors.New("ebpf init with Link failed: " + err.Error())
	}
	defer e.Close()

	Records := make(chan UniversalRecord, 100)
	{
		rd, err := ringbuf.NewReader(e.XDPObjects.XdpEventReportArea)
		if err != nil {
			return errors.New("ebpf ringbuf reader init fail: " + err.Error())
		}
		defer rd.Close()
		EndlessLoopReadXDPRecords(rd, Records)
	}
	{
		rd, err := ringbuf.NewReader(e.TCObjects.TcEventReportArea)
		if err != nil {
			return errors.New("ebpf ringbuf reader init fail: " + err.Error())
		}
		defer rd.Close()
		EndlessLoopReadTCRecords(rd, Records)
	}
	time.Sleep(1 * time.Second)
	defer close(Records)
	for r := range Records {
		fmt.Fprintf(os.Stdout, "Dropped Packect from %v:%d to %v:%d \n", r.Saddr, r.Sport, r.Daddr, r.Dport)
	}
	return nil
}

type UniversalRecord struct {
	Saddr net.IP
	Sport uint16
	Daddr net.IP
	Dport uint16
}

func EndlessLoopReadXDPRecords(rd *ringbuf.Reader, outChan chan<- UniversalRecord) {
	go func() {
		for {
			var CurrentRecord generated.XDPBpfXdpEvent
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &CurrentRecord); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}
			outChan <- UniversalRecord{
				Saddr: int2ip(CurrentRecord.Saddr),
				Sport: CurrentRecord.Sport,
				Daddr: int2ip(CurrentRecord.Daddr),
				Dport: CurrentRecord.Dport,
			}
		}
	}()
}

func EndlessLoopReadTCRecords(rd *ringbuf.Reader, outChan chan<- UniversalRecord) {
	go func() {
		for {
			var CurrentRecord generated.TCBpfTcEvent
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &CurrentRecord); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}
			outChan <- UniversalRecord{
				Saddr: int2ip(CurrentRecord.Saddr),
				Sport: CurrentRecord.Sport,
				Daddr: int2ip(CurrentRecord.Daddr),
				Dport: CurrentRecord.Dport,
			}
		}
	}()
}
