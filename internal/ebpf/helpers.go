package ebpf

import log "github.com/sirupsen/logrus"

// newEBPF returns a new loaded EBPF.
func newEBPF() (*EBPF, error) {
	log.Debug("Init ebpf Instance")
	e := New()
	if err := e.Load(); err != nil {
		return nil, err
	}

	return e, nil
}

// newEBPFWithLink returns a new loaded EBPF by loading the link.
func newEBPFWithLink() (*EBPF, error) {
	e, err := newEBPF()
	if err != nil {
		return nil, err
	}

	if err := e.LoadAttachedLink(); err != nil {
		return nil, err
	}

	return e, nil
}
