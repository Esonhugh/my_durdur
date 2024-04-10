package log

import (
	cobra_cmd "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd"
	"github.com/boratanrikulu/durdur/internal/ebpf"
	"github.com/spf13/cobra"
)

func init() {
	cobra_cmd.RootCmd.AddCommand(LogCmd)
}

var LogCmd = &cobra.Command{
	Use:   "log",
	Short: "print logs of dropping data",
	Long:  `print logs of dropping data`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ebpf.DropLogV2()
	},
}
