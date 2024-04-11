package undrop

import (
	"errors"
	"net"

	cobra_cmd "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd"
	"github.com/boratanrikulu/durdur/internal/ebpf"
	"github.com/spf13/cobra"
)

var UnDropOpt struct {
	SrcDirection bool
	DstDirection bool
	IP           string
	Port         uint16
}

func init() {
	cobra_cmd.RootCmd.AddCommand(UnDropCmd)
	UnDropCmd.PersistentFlags().BoolVar(&UnDropOpt.SrcDirection, "src", false, "Source direction")
	UnDropCmd.PersistentFlags().BoolVar(&UnDropOpt.DstDirection, "dst", false, "Destination direction")
	UnDropCmd.PersistentFlags().StringVarP(&UnDropOpt.IP, "ip", "i", "1.1.1.1", "IP address")
	UnDropCmd.PersistentFlags().Uint16VarP(&UnDropOpt.Port, "port", "p", 0, "Port number")
}

var UnDropCmd = &cobra.Command{
	Use:   "undrop",
	Short: "Add new IP/port to the maps.",
	Long:  `Add new IP/port to the maps.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if UnDropOpt.SrcDirection == UnDropOpt.DstDirection {
			return errors.New("you can't specify both src and dst directions or none of them")
		}
		var d ebpf.Direction
		if UnDropOpt.SrcDirection {
			d = ebpf.Ingress
		} else {
			d = ebpf.Egress
		}
		ipv4 := net.ParseIP(UnDropOpt.IP)
		return ebpf.UndropV2(d, ipv4, UnDropOpt.Port)
	},
}
