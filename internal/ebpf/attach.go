package ebpf

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var FS = "/sys/fs/bpf"

var (
	ErrAlreadyAttached = fmt.Errorf("durdur is already attached to the interface")
)

// Attach loads the eBPF program and attaches it to the kernel.
func Attach(iface *net.Interface) error {
	log.Infof("Trying to attach XDP and TC eBPF program to the %v.", iface.Name)
	e, err := newEBPF()
	if err != nil {
		return err
	}
	defer e.Close()

	return e.Attach(iface)
}

// Attach attaches eBPF program to the kernel.
func (e *EBPF) Attach(iface *net.Interface) error {
	if err := e.LoadAttachedLink(); err == nil {
		return fmt.Errorf(
			"%w: %s", ErrAlreadyAttached, iface.Name,
		)
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   e.XDPObjects.XdpDurdurDropFunc,
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}
	if err := l.Pin(e.linkPinnedXDPFile()); err != nil {
		return err
	}
	e.XDPLink = l

	l2, err := link.AttachTCX(link.TCXOptions{
		Program:   e.TCObjects.TcDurdurDropFunc,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return err
	}
	if err := l2.Pin(e.linkPinnedTCXFile()); err != nil {
		return err
	}
	e.TCLink = l2
	return nil
}

// LoadAttachedLink returns the pinned link from the FS.
func (e *EBPF) LoadAttachedLink() error {
	l, err := link.LoadPinnedLink(e.linkPinnedXDPFile(), &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("%s: %w", err, ErrAlreadyAttached)
	}
	e.XDPLink = l
	l2, err := link.LoadPinnedLink(e.linkPinnedTCXFile(), &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("%s: %w", err, ErrAlreadyAttached)
	}
	e.TCLink = l2
	return nil
}

// linkPinnedXDPFile returns FS file address for the link.
func (e *EBPF) linkPinnedXDPFile() string {
	return fmt.Sprintf("%s/%s", FS, "xdp_drop_func_link")
}

func (e *EBPF) linkPinnedTCXFile() string {
	return fmt.Sprintf("%s/%s", FS, "tc_drop_func_link")
}
