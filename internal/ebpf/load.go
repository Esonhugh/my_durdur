package ebpf

import (
	"fmt"

	"github.com/boratanrikulu/durdur/internal/generated"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// EBPF keeps eBPF Objects(BpfPrograms, BpfMaps) and Link.
type EBPF struct {
	Objects *generated.BpfObjects
	L       link.Link
	LTCX    link.Link
}

// New returns a new EBPF.
func New() *EBPF {
	return &EBPF{
		Objects: &generated.BpfObjects{},
	}
}

// Load loads pre-compiled eBPF program.
func (e *EBPF) Load() error {
	spec, err := generated.LoadBpf()
	if err != nil {
		return fmt.Errorf("load ebpf: %w", err)
	}

	// spec.Maps["drop_from_addrs"].Pinning = ebpf.PinByName
	// spec.Maps["drop_to_addrs"].Pinning = ebpf.PinByName
	// spec.Maps["event_report_area"].Pinning = ebpf.PinByName
	for k := range spec.Maps {
		spec.Maps[k].Pinning = ebpf.PinByName
	}

	spec.Programs["tc_durdur_drop_func"].AttachType = ebpf.AttachTCXEgress
	spec.Programs["tc_durdur_drop_func"].Type = ebpf.SkSKB
	for _, v := range spec.Programs {
		println(v.Name)
		println(v.AttachType)
		println(v.Type)
	}

	if err := spec.LoadAndAssign(e.Objects, &ebpf.CollectionOptions{
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
	if e.Objects != nil {
		if err := e.Objects.Close(); err != nil {
			return err
		}
	}

	if e.L != nil {
		if err := e.L.Close(); err != nil {
			return err
		}
	}

	return nil
}
