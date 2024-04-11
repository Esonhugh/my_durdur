package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/boratanrikulu/durdur/internal/generated"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func DropLog() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	e, err := newEBPFWithLink()
	if err != nil {
		return errors.New("ebpf init with Link failed: " + err.Error())
	}
	defer e.Close()

	wg := &sync.WaitGroup{}
	{
		go func() {
			wg.Add(1)
			rd, err := ringbuf.NewReader(e.XDPObjects.XdpEventReportArea)
			if err != nil {
				log.Errorf("ebpf ringbuf reader init fail: %s", err)
			}
			defer rd.Close()
			log.Println("Starting Log....")
			LooplyReadXDPRecords(rd)
			wg.Done()
		}()
	}
	{
		go func() {
			wg.Add(1)
			rd, err := ringbuf.NewReader(e.TCObjects.TcEventReportArea)
			if err != nil {
				log.Errorf("ebpf ringbuf reader init fail: " + err.Error())
			}
			defer rd.Close()
			go LooplyReadTCRecords(rd)
			wg.Done()
		}()
	}
	wg.Wait()
	return nil
}

func LooplyReadXDPRecords(rd *ringbuf.Reader) {
	var CurrentRecord generated.XDPBpfXdpEvent

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

		log.Printf("Dropped Packect from %v to %v ", int2ip(CurrentRecord.Saddr), int2ip(CurrentRecord.Daddr))
	}
}

func LooplyReadTCRecords(rd *ringbuf.Reader) {
	var CurrentRecord generated.TCBpfTcEvent

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

		log.Printf("Dropped Packect from %v to %v ", int2ip(CurrentRecord.Saddr), int2ip(CurrentRecord.Daddr))
	}
}
