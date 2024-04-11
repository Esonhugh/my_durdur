package detach

import (
	cobra_cmd "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd"
	"github.com/boratanrikulu/durdur/internal/ebpf"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	cobra_cmd.RootCmd.AddCommand(DetachCmd)
}

var DetachCmd = &cobra.Command{
	Use:   "detach",
	Short: "Detaches the program from the network.",
	Long:  `Detaches the program from the network.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := ebpf.Detach()
		if err == nil {
			log.Info("Detached from the network.")
		} else {
			log.Error("Failed to detach from the network.")
		}
		return err
	},
}
