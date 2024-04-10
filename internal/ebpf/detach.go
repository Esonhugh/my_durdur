package ebpf

import "errors"

// Detach detaches all pinned objects from the FS.
func Detach() error {
	e, err := newEBPFWithLink()
	if err != nil {
		return err
	}
	defer e.Close()

	return e.Detach()
}

type UnpinCloser interface {
	Unpin() error
	Close() error
}

func UnpinClose(e UnpinCloser) error {
	if err := e.Unpin(); err != nil {
		return err
	}
	if err := e.Close(); err != nil {
		return err
	}
	return nil
}

// Detach unpins and closes FS and maps.
func (e *EBPF) Detach() error {
	return errors.Join(
		UnpinClose(e.XDPLink),
		UnpinClose(e.TCLink),
		UnpinClose(e.XDPObjects.XdpDurdurDropFunc),
		UnpinClose(e.XDPObjects.DropFromAddrs),
		UnpinClose(e.XDPObjects.DropFromPorts),
		UnpinClose(e.XDPObjects.DropFromIpport),
		UnpinClose(e.XDPObjects.XdpEventReportArea),
		UnpinClose(e.TCObjects.TcDurdurDropFunc),
		UnpinClose(e.TCObjects.DropToAddrs),
		UnpinClose(e.TCObjects.DropToPorts),
		UnpinClose(e.TCObjects.DropToIpport),
		UnpinClose(e.TCObjects.TcEventReportArea),
		e.Close(),
	)
}
