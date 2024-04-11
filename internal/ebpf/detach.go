package ebpf

import (
	"errors"
	"fmt"
	"os"
)

// Detach detaches all pinned objects from the FS.
func Detach() error {
	e, err := newEBPFWithLink()
	if err != nil {
		return err
	}

	if os.Remove(e.linkPinnedXDPFile()) != nil {
		return fmt.Errorf("failed to remove XDP pinned file")
	}

	if os.Remove(e.linkPinnedTCXFile()) != nil {
		return fmt.Errorf("failed to remove TC pinned file")
	}
	return e.Detach()
}

type UnpinCloser interface {
	Unpin() error
	Close() error
}

func Unpin(e UnpinCloser) error {
	if err := e.Unpin(); err != nil {
		return err
	}
	return nil
}

func Close(e UnpinCloser) error {
	if err := e.Close(); err != nil {
		return err
	}
	return nil
}

// Detach unpins and closes FS and maps.
func (e *EBPF) Detach() error {
	return errors.Join(
		Unpin(e.XDPObjects.XdpDurdurDropFunc),
		Unpin(e.TCObjects.TcDurdurDropFunc),
		Unpin(e.XDPObjects.DropFromAddrs),
		Unpin(e.XDPObjects.DropFromPorts),
		Unpin(e.XDPObjects.DropFromIpport),
		Unpin(e.TCObjects.DropToAddrs),
		Unpin(e.TCObjects.DropToPorts),
		Unpin(e.TCObjects.DropToIpport),
		Unpin(e.XDPObjects.XdpEventReportArea),
		Unpin(e.TCObjects.TcEventReportArea),
		e.Close(),
	)
}
