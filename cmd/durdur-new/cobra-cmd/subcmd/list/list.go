package list

import (
	cobra_cmd "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd"
	"github.com/boratanrikulu/durdur/internal/ebpf"
	"github.com/spf13/cobra"
)

func init() {
	cobra_cmd.RootCmd.AddCommand(ListCmd)
}

var ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all the rules",
	Long:  `List all the rules`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ebpf.ListRules()
	},
}
