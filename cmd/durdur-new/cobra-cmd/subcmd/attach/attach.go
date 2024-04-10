package attach

import (
	"fmt"
	"net"

	cobra_cmd "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd"
	"github.com/boratanrikulu/durdur/internal/ebpf"
	"github.com/spf13/cobra"
)

var AttachOpt struct {
	InterfaceName string
}

func init() {
	cobra_cmd.RootCmd.AddCommand(AttachCmd)
	AttachCmd.PersistentFlags().StringVarP(&AttachOpt.InterfaceName, "interface", "i", "eth0", "network interface")
}

var AttachCmd = &cobra.Command{
	Use:   "attach",
	Short: "Attaches the program to the network.",
	Long:  `Attaches the program to the network.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ifaceName := AttachOpt.InterfaceName
		iface, err := net.InterfaceByName(AttachOpt.InterfaceName)
		if err != nil {
			return fmt.Errorf("lookup network iface %q: %w", ifaceName, err)
		}

		return ebpf.Attach(iface)
	},
}
