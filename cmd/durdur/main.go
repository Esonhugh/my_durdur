package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"
)

func init() {

}

func main() {
	app := &cli.App{
		Name:  "Durdur",
		Usage: "Durdur is a L4 package dropper.",
		Commands: []*cli.Command{
			AttachCmd(),
			DetachCmd(),
			DropCmd(),
			UndropCmd(),
			LogCmd(),
		},
	}
	log.SetLevel(log.TraceLevel)
	if err := app.Run(os.Args); err != nil {
		log.Fatalln(err)
	}
}
