package ebpf

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/boratanrikulu/durdur/internal/generated"
	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
)

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func ip2intL(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.LittleEndian.Uint32(ip[12:16])
	}
	return binary.LittleEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

type XDPIPPort generated.XDPBpfXdpIpport
type TCIPPort generated.TCBpfTcIpport
type XDPEvent generated.XDPBpfXdpEvent
type TCEvent generated.TCBpfTcEvent

func ParseEbpfVerifierError(err error) {
	var VerifierError *ebpf.VerifierError
	if errors.As(err, &VerifierError) {
		log.Debugln("Is a Verifier error!")
		for l, v := range VerifierError.Log {
			log.Debugf("%v: %v", l, v)
		}
		log.Debugf("Truncated: %v", VerifierError.Truncated)
		log.Debugf("Case: %v", VerifierError.Cause)
		log.Debugf("last 10 line Error: %-10v", VerifierError)
	}
	return
}

func DebugSpec(spec *ebpf.CollectionSpec) {
	for _, v := range spec.Maps {
		log.Debugf("Map: %s", v.Name)
		log.Debugf("Map Type: %s", v.Type)
		log.Debugf("Map Pinning: %s", v.Pinning)
		log.Debugf("Map Key Size: %d", v.KeySize)
		log.Debugf("Map Value Size: %d", v.ValueSize)
		log.Debugf("Map Max Entries: %d", v.MaxEntries)
		log.Debugf("Map Flags: %d", v.Flags)
	}
	for _, v := range spec.Programs {
		log.Debugf("Program: %s", v.Name)
		log.Debugf("Program Type: %s", v.Type)
		log.Debugf("Program Attach Type: %s", v.AttachType)
		log.Debugf("Program Attach to: %s", v.AttachTo)
		log.Debugf("Program Attach Target: %s", v.AttachTarget)
	}
}
