package main

import (
	"context"
	"fmt"
	"github.com/haruue-net/wg-apply/wgconf"
	"github.com/haruue-net/wg-apply/wgdiff"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"os"
	"strings"
)

import (
	_ "github.com/haruue-net/wg-apply/wgconf/wgquick"
)

var (
	Version = "Development"
)

var rootCmd = &cobra.Command{
	Use:          "wg-apply [ INTERFACE | CONFIG_FILE ]",
	Version:      Version,
	RunE:         Run,
	SilenceUsage: true,
}

func Run(cmd *cobra.Command, args []string) (err error) {
	wgc, err := wgctrl.New()
	if err != nil {
		err = fmt.Errorf("cannot obtains wgctrl client: %w", err)
		return
	}
	defer wgc.Close()

	ifce := viper.GetString("interface")
	file := viper.GetString("file")
	parser := viper.GetString("parser")
	skipNetwork := viper.GetBool("skip-network")

	var extraArg string
	if len(args) > 0 {
		extraArg = args[0]
	}
	if extraArg != "" {
		if ifce != "" && file != "" {
			err = fmt.Errorf("redundant argument: %s", extraArg)
			return
		}
		if ifce == "" && file == "" {
			if strings.ContainsAny(extraArg, "/") {
				file = extraArg
			} else {
				ifce = extraArg
			}
		} else if ifce == "" {
			if strings.ContainsAny(extraArg, "/") {
				err = fmt.Errorf("redundant argument or invalid interface name: %s", extraArg)
				return
			}
			ifce = extraArg
		} else {
			// file == ""
			file = extraArg
		}
	}

	conf, err := wgconf.Parse(context.Background(), parser, ifce, file)
	if err != nil {
		return
	}

	if !skipNetwork {
		err = conf.Network.ApplyNetworkConfig()
		if err != nil {
			err = fmt.Errorf("failed to apply network config changes: %w", err)
			return
		}
	}

	device, err := wgc.Device(conf.Interface)
	if err != nil {
		var hintSkipNetwork string
		if skipNetwork {
			hintSkipNetwork = " (try remove --skip-network or -N flag)"
		}
		err = fmt.Errorf("wireguard interface %s is not exist%s: %w", conf.Interface, hintSkipNetwork, err)
		return
	}
	diff, err := wgdiff.CalcDiff(device, &conf.WireGuard)
	if err != nil {
		err = fmt.Errorf("failed to calculate diff: %w", err)
		return
	}
	err = wgc.ConfigureDevice(conf.Interface, *diff)
	if err != nil {
		err = fmt.Errorf("failed to apply wireguard config changes: %w", err)
		return
	}
	return
}

func init() {
	rootCmd.PersistentFlags().StringP("interface", "i", "", "wireguard interface to config")
	_ = viper.BindPFlag("interface", rootCmd.PersistentFlags().Lookup("interface"))

	rootCmd.PersistentFlags().StringP("file", "f", "", "wireguard config file path")
	_ = viper.BindPFlag("file", rootCmd.PersistentFlags().Lookup("file"))

	rootCmd.PersistentFlags().StringP("parser", "p", "", "config parser to use")
	_ = viper.BindPFlag("parser", rootCmd.PersistentFlags().Lookup("parser"))

	rootCmd.PersistentFlags().BoolP("skip-network", "N", false, "skip changes on network adapter (interface, addresses, routes)")
	_ = viper.BindPFlag("skip-network", rootCmd.PersistentFlags().Lookup("skip-network"))
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(int(unix.EINVAL))
	}
}
