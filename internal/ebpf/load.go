package ebpf

import (
	"fmt"

	"github.com/boratanrikulu/durdur/internal/generated"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"

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
	rlimit.RemoveMemlock()
	return &EBPF{
		XDPObjects: &generated.XDPBpfObjects{},
		TCObjects:  &generated.TCBpfObjects{},
	}
}

// Load loads pre-compiled eBPF program.
func (e *EBPF) Load() error {
	log.Debug("Loading eBPF programs")
	{
		log.Debug("1. Loading XDP eBPF program")
		spec, err := generated.LoadXDPBpf()
		if err != nil {
			log.Errorf("Failed to load XDP eBPF program: %v", err)
			return fmt.Errorf("load ebpf: %w", err)
		}
		// spec.Maps["drop_to_addrs"].Pinning = ebpf.PinByName
		// spec.Maps["event_report_area"].Pinning = ebpf.PinByName
		for k := range spec.Maps {
			spec.Maps[k].Pinning = ebpf.PinByName
		}
		DebugSpec(spec)
		if err := spec.LoadAndAssign(e.XDPObjects, &ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: FS,
			},
			Programs: ebpf.ProgramOptions{
				LogLevel: ebpf.LogLevelInstruction,
			},
		}); err != nil {
			log.Errorf("Failed to load and assign XDP eBPF program: %v", err)
			ParseEbpfVerifierError(err)
			return fmt.Errorf("load and assign: %w", err)
		}
		log.Info("Load XDP eBPF program successfully")
	}
	{
		log.Debug("2. Loading TC eBPF program")
		spec, err := generated.LoadTCBpf()
		if err != nil {
			log.Errorf("Failed to load TC eBPF program: %v", err)
			return fmt.Errorf("load ebpf: %w", err)
		}
		for k := range spec.Maps {
			spec.Maps[k].Pinning = ebpf.PinByName
		}
		DebugSpec(spec)
		if err := spec.LoadAndAssign(e.TCObjects, &ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: FS,
			},
			Programs: ebpf.ProgramOptions{
				LogLevel: ebpf.LogLevelInstruction,
			},
		}); err != nil {
			log.Errorf("Failed to load and assign TC eBPF program: %v", err)
			return fmt.Errorf("load and assign: %w", err)
		}
		log.Info("Load TC eBPF program successfully")
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

	if e.TCObjects != nil {
		if err := e.TCObjects.Close(); err != nil {
			return err
		}
	}

	if e.TCLink != nil {
		if err := e.TCLink.Close(); err != nil {
			return err
		}
	}
	return nil
}
