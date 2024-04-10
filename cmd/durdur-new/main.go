package durdur_new

import (
	cmd "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd"
	_ "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd/subcmd/attach"
	_ "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd/subcmd/detach"
	_ "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd/subcmd/drop"
	_ "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd/subcmd/log"
	_ "github.com/boratanrikulu/durdur/cmd/durdur-new/cobra-cmd/subcmd/undrop"
)

func main() {
	cmd.Exec()
}
