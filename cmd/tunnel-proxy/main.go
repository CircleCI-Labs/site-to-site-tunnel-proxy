package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	"github.com/circleci/site-to-site-tunnel-proxy/cmd"
	"github.com/circleci/site-to-site-tunnel-proxy/proxy"
)

type CLI struct {
	Serve   proxy.ServeCmd   `cmd:"" help:"Run HTTP CONNECT proxy server."`
	Connect proxy.ConnectCmd `cmd:"" help:"Stdio connect mode for SSH ProxyCommand."`
	Version VersionCmd       `cmd:"" help:"Print version and exit."`
}

type VersionCmd struct{}

func (v *VersionCmd) Run() error {
	fmt.Printf("tunnel-proxy %s (%s)\n", cmd.Version, cmd.Date)
	return nil
}

func main() {
	cli := CLI{}
	ctx := kong.Parse(&cli,
		kong.Name("tunnel-proxy"),
		kong.Description("Site-to-site tunnel proxy for CircleCI private VCS connectivity."),
	)
	if err := ctx.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
