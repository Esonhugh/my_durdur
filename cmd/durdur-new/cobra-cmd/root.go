package cobra_cmd

import (
	"github.com/boratanrikulu/durdur/internal/ebpf"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	easy "github.com/t-tomalak/logrus-easy-formatter"
)

var (
	BPFfs string
	debug bool
)

func init() {
	RootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug mode")
	RootCmd.PersistentFlags().StringVarP(&BPFfs, "bpffs", "b", "/sys/fs/bpf", "mounted bpffs location")
}

var RootCmd = &cobra.Command{
	Use:   "durdur",
	Short: `Durdur is a L4 package Dropper/Firewall.`,
	Long:  `Durdur is a L4 package Dropper/Firewall.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if debug {
			log.SetLevel(log.TraceLevel)
		} else {
			log.SetLevel(log.InfoLevel)
		}
		ebpf.FS = BPFfs
	},
}

func Exec() {
	log.SetFormatter(&easy.Formatter{
		LogFormat: "%msg%",
	})
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
