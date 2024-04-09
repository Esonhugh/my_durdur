package ebpf

import (
	"fmt"

	"github.com/boratanrikulu/durdur/internal/generated"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// EBPF keeps eBPF Objects(BpfPrograms, BpfMaps) and Link.
type EBPF struct {
	XDPObjects *generated.XDPBpfObjects
	XDPLink    link.Link
	TCObjects  *generated.TCBpfObjects
	TCLink     link.Link
}

// New returns a new EBPF.
func New() *EBPF {
	return &EBPF{
		XDPObjects: &generated.XDPBpfObjects{},
		TCObjects:  &generated.TCBpfObjects{},
	}
}

// Load loads pre-compiled eBPF program.
func (e *EBPF) Load() error {
	spec, err := generated.LoadXDPBpf()
	if err != nil {
		return fmt.Errorf("load ebpf: %w", err)
	}

	// spec.Maps["drop_from_addrs"].Pinning = ebpf.PinByName
	// spec.Maps["drop_to_addrs"].Pinning = ebpf.PinByName
	// spec.Maps["event_report_area"].Pinning = ebpf.PinByName
	for k := range spec.Maps {
		spec.Maps[k].Pinning = ebpf.PinByName
	}

	if err := spec.LoadAndAssign(e.XDPObjects, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: FS,
		},
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	}); err != nil {
		return fmt.Errorf("load and assign: %w", err)
	}

	return nil
}

// Close cleans all resources.
func (e *EBPF) Close() error {
	if e.XDPObjects != nil {
		if err := e.XDPObjects.Close(); err != nil {
			return err
		}
	}

	if e.XDPLink != nil {
		if err := e.XDPLink.Close(); err != nil {
			return err
		}
	}

	return nil
}
