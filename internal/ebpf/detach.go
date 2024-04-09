package ebpf

import (
	"fmt"
)

// Detach detaches all pinned objects from the FS.
func Detach() error {
	e, err := newEBPFWithLink()
	if err != nil {
		return err
	}
	defer e.Close()

	return e.Detach()
}

// Detach unpins and closes FS and maps.
func (e *EBPF) Detach() error {
	if err := e.XDPLink.Unpin(); err != nil {
		return fmt.Errorf("detach the link: %w", err)
	}

	if err := e.XDPObjects.Close(); err != nil {
		return fmt.Errorf("close the link: %w", err)
	}

	if err := e.XDPObjects.XDPBpfMaps.DropFromAddrs.Unpin(); err != nil {
		return fmt.Errorf("detach %s map: %w",
			e.XDPObjects.XDPBpfMaps.DropFromAddrs.String(), err)
	}

	if err := e.XDPObjects.XDPBpfMaps.DropFromAddrs.Close(); err != nil {
		return fmt.Errorf("detach %s map: %w",
			e.XDPObjects.XDPBpfMaps.DropFromAddrs.String(), err)
	}

	return nil
}
