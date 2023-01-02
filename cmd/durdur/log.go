package main

import (
	"github.com/boratanrikulu/durdur/internal/ebpf"
	"github.com/urfave/cli/v2"
)

func LogCmd() *cli.Command {
	return &cli.Command{
		Name:   "log",
		Usage:  "print logs of dropping data",
		Action: droplog,
	}
}

func droplog(c *cli.Context) error {
	return ebpf.DropLog()
}
