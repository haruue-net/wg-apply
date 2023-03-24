package wgquick

import (
	"context"
	"errors"
	"fmt"
	"github.com/haruue-net/wg-apply/ini"
	"github.com/haruue-net/wg-apply/netconf"
	"github.com/haruue-net/wg-apply/wgconf"
	"github.com/jsimonetti/rtnetlink/rtnl"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func init() {
	wgconf.RegisterParser("wg-quick", parse)
}

func parse(ctx context.Context) (conf *wgconf.Config, err error) {
	ifceName := ""
	confPath := ""

	opts := wgconf.ExtractParserOptions(ctx)
	if opts == nil {
		err = errors.New("missing parser options")
		return
	}
	if opts.Interface == "" && opts.Path == "" {
		err = errors.New("missing interface name or conf file path")
		return
	}
	if opts.Path != "" {
		if opts.ProbeParser {
			absPath, aerr := filepath.Abs(opts.Path)
			if aerr != nil {
				absPath = opts.Path
			}
			if filepath.Dir(absPath) != "/etc/wireguard" {
				err = wgconf.ErrProbeParserMismatch
				return
			}
			if path.Ext(absPath) != ".conf" {
				err = wgconf.ErrProbeParserMismatch
				return
			}
		}
		confPath = opts.Path
		if opts.Interface == "" {
			ifceName = strings.TrimSuffix(path.Base(opts.Path), ".conf")
		}
	} else /* opts.Interface != "" && opts.Path == "" */ {
		ifceName = opts.Interface
		confPath = fmt.Sprintf("/etc/wireguard/%s.conf", ifceName)
		if ferr := unix.Access(confPath, unix.R_OK); ferr != nil {
			if opts.ProbeParser {
				err = wgconf.ErrProbeParserMismatch
			} else {
				err = fmt.Errorf("failed to access conf file %s: %w", confPath, ferr)
			}
			return
		}
	}

	confFile, err := os.Open(confPath)
	if err != nil {
		err = fmt.Errorf("failed to open conf file %s: %w", confPath, err)
		return
	}
	defer confFile.Close()

	iniFile, err := ini.ParseINI(confFile)
	if err != nil {
		err = fmt.Errorf("failed to parse conf file: %w", err)
		return
	}

	networkConf := &netconf.NetworkConfig{
		Device: ifceName,
	}

	conf = &wgconf.Config{
		Interface: ifceName,
		WireGuard: wgtypes.Config{},
		Network:   networkConf,
	}

	addAllowedIPsAsRoutes := true

	rtTables, err := parseIproute2RtTables()
	if err != nil {
		log.Printf("[warn] failed to parse iproute2 rt_tables: %v", err)
		rtTables = map[string]uint32{}
	}

	for _, section := range iniFile {
		switch section.Name {
		case "Interface":
			for _, pair := range section.Pairs {
				switch pair.Key {
				case "Address":
					addrs := strings.Split(pair.Value, ",")
					for _, addrStr := range addrs {
						addrStr = strings.TrimSpace(addrStr)
						if addrStr == "" {
							continue
						}
						var address *net.IPNet
						address, err = rtnl.ParseAddr(addrStr)
						if err != nil {
							err = fmt.Errorf("failed to parse address %s in \"Address = %s\": %w", addrStr, pair.Value, err)
							return
						}
						networkConf.Addresses = append(networkConf.Addresses, *address)
					}
				case "MTU":
					var mtu int
					mtu, err = strconv.Atoi(pair.Value)
					if err != nil {
						err = fmt.Errorf("failed to parse MTU %s: %w", pair.Value, err)
						return
					}
					if mtu < 0 || mtu > 65535 {
						err = fmt.Errorf("invalid MTU %d", mtu)
						return
					}
					mtu32 := uint32(mtu)
					networkConf.MTU = &mtu32
				case "PrivateKey":
					var privkey wgtypes.Key
					privkey, err = wgtypes.ParseKey(pair.Value)
					if err != nil {
						err = fmt.Errorf("failed to parse private key in \"PrivateKey = %s\": %w", pair.Value, err)
						return
					}
					conf.WireGuard.PrivateKey = &privkey
				case "ListenPort":
					var port int
					port, err = strconv.Atoi(pair.Value)
					if err != nil {
						err = fmt.Errorf("failed to parse listen port in \"ListenPort = %s\": %w", pair.Value, err)
						return
					}
					if port < 0 || port > 65535 {
						err = fmt.Errorf("invalid listen port %d", port)
						return
					}
					conf.WireGuard.ListenPort = &port
				case "Table":
					switch pair.Value {
					case "off":
						addAllowedIPsAsRoutes = false
					case "auto":
						networkConf.Table = nil
					default:
						var table32 uint32
						table, terr := strconv.ParseUint(pair.Value, 0, 32)
						if terr == nil {
							// table number
							if table < 0 || table > 1<<32-1 {
								err = fmt.Errorf("invalid table number %d", table)
								return
							}
							table32 = uint32(table)
						} else {
							// table name
							var ok bool
							table32, ok = rtTables[pair.Value]
							if !ok {
								err = fmt.Errorf("unknown table %s", pair.Value)
								return
							}
						}
						networkConf.Table = &table32
					}
				case "FwMark":
					var fwmark64 uint64
					fwmark64, err = strconv.ParseUint(pair.Value, 0, 32)
					if err != nil {
						err = fmt.Errorf("failed to parse fwmark in \"FwMark = %s\": %w", pair.Value, err)
						return
					}
					fwmark := int(uint32(fwmark64))
					conf.WireGuard.FirewallMark = &fwmark
				case "DNS", "PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig":
					// unsupported
				default:
					err = fmt.Errorf("unknown key-value pair in [Interface] section: %s = %s", pair.Key, pair.Value)
					return nil, err
				}
			}
		case "Peer":
			peer := wgtypes.PeerConfig{
				ReplaceAllowedIPs: true,
			}
			for _, pair := range section.Pairs {
				switch pair.Key {
				case "PublicKey":
					var pubkey wgtypes.Key
					pubkey, err = wgtypes.ParseKey(pair.Value)
					if err != nil {
						err = fmt.Errorf("failed to parse public key in \"PublicKey = %s\": %w", pair.Value, err)
						return
					}
					peer.PublicKey = pubkey
				case "PresharedKey":
					var psk wgtypes.Key
					psk, err = wgtypes.ParseKey(pair.Value)
					if err != nil {
						err = fmt.Errorf("failed to parse preshared key in \"PresharedKey = %s\": %w", pair.Value, err)
						return
					}
					peer.PresharedKey = &psk
				case "AllowedIPs":
					prefixes := strings.Split(pair.Value, ",")
					for _, prefixStr := range prefixes {
						prefixStr = strings.TrimSpace(prefixStr)
						if prefixStr == "" {
							continue
						}
						var prefix *net.IPNet
						_, prefix, err = net.ParseCIDR(prefixStr)
						if err != nil {
							err = fmt.Errorf("failed to parse prefix %s in \"AllowedIPs = %s\": %w", prefixStr, pair.Value, err)
							return
						}
						peer.AllowedIPs = append(peer.AllowedIPs, *prefix)
					}
				case "Endpoint":
					peer.Endpoint, err = net.ResolveUDPAddr("udp", pair.Value)
					if err != nil {
						err = fmt.Errorf("failed to parse endpoint in \"Endpoint = %s\": %w", pair.Value, err)
						return
					}
				case "PersistentKeepalive":
					var keepalive int
					keepalive, err = strconv.Atoi(pair.Value)
					if err != nil {
						err = fmt.Errorf("failed to parse persistent keepalive in \"PersistentKeepalive = %s\": %w", pair.Value, err)
						return
					}
					if keepalive < 0 || keepalive > 65535 {
						err = fmt.Errorf("invalid persistent keepalive %d", keepalive)
						return
					}
					keepaliveDuration := time.Duration(keepalive) * time.Second
					peer.PersistentKeepaliveInterval = &keepaliveDuration
				default:
					err = fmt.Errorf("unknown key-value pair in [Peer] section: %s = %s", pair.Key, pair.Value)
					return nil, err
				}
			}
			conf.WireGuard.Peers = append(conf.WireGuard.Peers, peer)
		}
	}

	if addAllowedIPsAsRoutes {
		for _, peer := range conf.WireGuard.Peers {
			for _, prefix := range peer.AllowedIPs {
				networkConf.Routes = append(networkConf.Routes, prefix)
			}
		}
	}

	return
}
