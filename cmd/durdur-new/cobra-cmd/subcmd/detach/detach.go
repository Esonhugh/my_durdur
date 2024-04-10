package detach

import (
	cobra_cmd "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd"
	"github.com/boratanrikulu/durdur/internal/ebpf"
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
		return ebpf.Detach()
	},
}
