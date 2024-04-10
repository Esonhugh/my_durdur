package ebpf

import (
	"encoding/binary"
	"net"

	"github.com/boratanrikulu/durdur/internal/generated"
)

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

type DNSQuery generated.XDPBpfDnsquery
type XDPIPPort generated.XDPBpfXdpIpport
type TCIPPort generated.TCBpfTcIpport
type XDPEvent generated.XDPBpfXdpEvent
type TCEvent generated.TCBpfTcEvent
