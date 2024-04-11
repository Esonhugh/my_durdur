package drop

import (
	"errors"
	"net"

	cobra_cmd "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd"
	"github.com/boratanrikulu/durdur/internal/ebpf"
	"github.com/spf13/cobra"
)

var DropOpt struct {
	SrcDirection bool
	DstDirection bool
	IP           string
	Port         uint16
}

func init() {
	cobra_cmd.RootCmd.AddCommand(DropCmd)
	DropCmd.PersistentFlags().BoolVar(&DropOpt.SrcDirection, "src", false, "Source direction")
	DropCmd.PersistentFlags().BoolVar(&DropOpt.DstDirection, "dst", false, "Destination direction")
	DropCmd.PersistentFlags().StringVarP(&DropOpt.IP, "ip", "i", "", "IP address")
	DropCmd.PersistentFlags().Uint16VarP(&DropOpt.Port, "port", "p", 0, "Port number")
}

var DropCmd = &cobra.Command{
	Use:   "drop",
	Short: "Add new IP/port to the maps.",
	Long:  `Add new IP/port to the maps.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if DropOpt.SrcDirection == DropOpt.DstDirection {
			return errors.New("you can't specify both src and dst directions or none of them")
		}
		var d ebpf.Direction
		if DropOpt.SrcDirection {
			d = ebpf.Ingress
		} else {
			d = ebpf.Egress
		}
		if DropOpt.IP == "" {

		}
		ipv4 := net.ParseIP(DropOpt.IP)
		return ebpf.DropV2(d, ipv4, DropOpt.Port)
	},
}
