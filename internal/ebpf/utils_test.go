package ebpf

import (
	"net"
	"testing"
)

func TestIPandInt(t *testing.T) {
	ip := net.ParseIP("192.168.1.2")
	if ip == nil {
		t.Error("Could not parse IP")
	}
	ipint := ip2int(ip)
	t.Log(ipint)
	r_ip := int2ip(ipint)
	t.Log(r_ip)
	if !ip.Equal(r_ip) {
		t.Error("IPs are not equal")
	}
}
