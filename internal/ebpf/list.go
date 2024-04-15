package ebpf

import (
	js "encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
)

func ListRules(json bool) error {
	e, err := newEBPFWithLink()
	if err != nil {
		return err
	}
	defer e.Close()

	records := e.ListMap()
	if len(records) == 0 {
		log.Infof("No rules attached")
	}

	if json {
		if len(records) == 0 {
			fmt.Fprintf(os.Stdout, "[]")
			return nil
		}
		b, e := js.Marshal(records)
		fmt.Fprintf(os.Stdout, string(b))
		return e
	}

	fmt.Fprintf(os.Stdout, "\n")
	t := &Table{
		Header: []string{"source", "direction-and-type", "target", "count of breaching"},
		Body:   make([][]string, 0),
	}
	for _, record := range records {
		if record.IP == nil {
			record.IP = net.IPv4zero
		}

		if record.Port == 0 {
			record.rPort = "any"
		} else {
			record.rPort = fmt.Sprintf("%v", record.Port)
		}

		if record.D == Egress {
			t.Body = append(t.Body, []string{
				// "host:any", "---X-(egress)-X--->", fmt.Sprintf("%v:%v", record.IP, record.rPort),
				fmt.Sprintf("%v:%v", record.IP, record.rPort), "<---X-(egress)-X---", "host:any", fmt.Sprintf("%v", record.Count),
			})
		} else {
			t.Body = append(t.Body, []string{
				fmt.Sprintf("%v:any", record.IP), "---X-(ingress)-X--->", fmt.Sprintf("host:%v", record.rPort), fmt.Sprintf("%v", record.Count),
			})
		}
	}
	t.Print()
	return nil
}

type Table struct {
	Header []string
	Body   [][]string
}

func (t Table) Print() {
	newTable := tablewriter.NewWriter(os.Stdout)
	newTable.SetAutoMergeCells(false)
	newTable.SetRowLine(false)
	newTable.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	newTable.SetAlignment(tablewriter.ALIGN_LEFT)
	newTable.SetBorder(false)
	newTable.SetRowSeparator("")
	newTable.SetColumnSeparator("")
	newTable.SetHeaderLine(false)
	newTable.SetHeader(t.Header)
	newTable.AppendBulk(t.Body)
	newTable.Render()
}

type eBPFRecord struct {
	D     Direction `json:"direction"`
	IP    net.IP    `json:"ip"`
	Port  uint16    `json:"port"`
	rPort string
	Count uint64 `json:"hit-rule"`
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
			record = append(record, eBPFRecord{D: Ingress, IP: int2ipL(key.Addr), Port: htons(key.Port), Count: value})
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
			record = append(record, eBPFRecord{D: Egress, IP: int2ipL(key.Addr), Port: htons(key.Port), Count: value})
		}
	}

	return record
}
