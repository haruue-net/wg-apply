package netconf

import (
	"fmt"
	"github.com/jsimonetti/rtnetlink"
	"github.com/jsimonetti/rtnetlink/rtnl"
	"golang.org/x/sys/unix"
	"log"
	"net"
)

type NetworkConfig struct {
	Device    string
	MTU       *uint32
	Addresses []net.IPNet
	Routes    []net.IPNet
	Table     *uint32
}

func (c *NetworkConfig) ApplyNetworkConfig() (err error) {
	conn, err := rtnl.Dial(nil)
	if err != nil {
		err = fmt.Errorf("failed to establish netlink conn: %w", err)
		return
	}
	defer conn.Close()

	ifceIdx, err := c.ensureWireGuardInterface(conn.Conn)
	if err != nil {
		err = fmt.Errorf("failed to ensure wireguard interface: %w", err)
		return
	}
	ifce, err := conn.LinkByIndex(int(ifceIdx))
	if err != nil {
		err = fmt.Errorf("failed to get wireguard interface by index: %w", err)
		return
	}
	err = c.updateAddresses(conn, ifce)
	if err != nil {
		err = fmt.Errorf("failed to update addresses: %w", err)
		return
	}
	err = c.updateRoutes(conn, ifce)
	if err != nil {
		err = fmt.Errorf("failed to update routes: %w", err)
		return
	}
	return
}

func (c *NetworkConfig) ensureWireGuardInterface(conn *rtnetlink.Conn) (ifceIndex uint32, err error) {
	links, err := conn.Link.List()
	if err != nil {
		err = fmt.Errorf("failed to list wireguard interfaces: %w", err)
		return
	}
	for _, link := range links {
		if link.Attributes.Name == c.Device {
			ifceIndex = link.Index
			if link.Attributes.Info.Kind != "wireguard" {
				err = fmt.Errorf("interface %s is not a wireguard interface", c.Device)
				return
			}
			mtu := uint32(1420)
			if c.MTU != nil {
				mtu = *c.MTU
			}
			log.Printf("updating wireguard interface %s mtu %d ...", c.Device, mtu)
			err = conn.Link.Set(&rtnetlink.LinkMessage{
				Family: unix.AF_UNSPEC,
				Index:  ifceIndex,
				Flags:  unix.IFF_UP,
				Attributes: &rtnetlink.LinkAttributes{
					MTU: mtu,
				},
			})
			return
		}
	}
	ifceIndex, err = c.setupWireGuardInterface(conn)
	if err != nil {
		err = fmt.Errorf("failed to setup wireguard interface: %w", err)
		return
	}
	return
}

func (c *NetworkConfig) setupWireGuardInterface(conn *rtnetlink.Conn) (ifceIndex uint32, err error) {
	mtu := uint32(1420)
	if c.MTU != nil {
		mtu = *c.MTU
	}
	log.Printf("creating wireguard interface %s mtu %d ...", c.Device, mtu)
	err = conn.Link.New(&rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Flags:  unix.IFF_UP,
		Attributes: &rtnetlink.LinkAttributes{
			Name: c.Device,
			Info: &rtnetlink.LinkInfo{Kind: "wireguard"},
			MTU:  mtu,
		},
	})
	if err != nil {
		err = fmt.Errorf("failed to create wireguard interface: %w", err)
		return
	}
	links, err := conn.Link.ListByKind("wireguard")
	if err != nil {
		err = fmt.Errorf("failed to list wireguard interfaces: %w", err)
		return
	}
	for _, link := range links {
		if link.Attributes.Name == c.Device {
			ifceIndex = link.Index
			return
		}
	}
	err = fmt.Errorf("failed to find wireguard interface after setup")
	return
}

func (c *NetworkConfig) updateAddresses(conn *rtnl.Conn, ifce *net.Interface) (err error) {
	addrToString := func(n net.IPNet) string {
		ones, _ := n.Mask.Size()
		return fmt.Sprintf("%s/%d", n.IP.String(), ones)
	}

	oldAddrs := map[string]net.IPNet{}
	{
		var oas []*net.IPNet
		oas, err = conn.Addrs(ifce, unix.AF_UNSPEC)
		if err != nil {
			err = fmt.Errorf("failed to get old addresses: %w", err)
			return
		}
		for _, oa := range oas {
			oldAddrs[addrToString(*oa)] = *oa
		}
	}

	newAddrs := map[string]net.IPNet{}
	for _, na := range c.Addresses {
		newAddrs[addrToString(na)] = na
	}

addrDedupRouteOuter:
	for oak := range oldAddrs {
		for nak := range newAddrs {
			if oak == nak {
				// remove common elements, then oldAddrs will be the addresses to delete,
				// and newAddrs will be the addresses to add
				delete(oldAddrs, oak)
				delete(newAddrs, nak)
				continue addrDedupRouteOuter
			}
		}
	}

	for s, addr := range oldAddrs {
		log.Printf("[#] ip address del %s dev %s", s, c.Device)
		err = conn.AddrDel(ifce, &addr)
		if err != nil {
			err = fmt.Errorf("failed to delete old address %s on interface %s: %w", addr.String(), c.Device, err)
			return
		}
	}

	for s, addr := range newAddrs {
		log.Printf("[#] ip address add %s dev %s", s, c.Device)
		err = conn.AddrAdd(ifce, &addr)
		if err != nil {
			err = fmt.Errorf("failed to add new address %s on interface %s: %w", addr.String(), c.Device, err)
			return
		}
	}

	return
}

func (c *NetworkConfig) updateRoutes(conn *rtnl.Conn, ifce *net.Interface) (err error) {
	toIPNet := func(route *rtnetlink.RouteMessage) net.IPNet {
		return net.IPNet{
			IP:   route.Attributes.Dst,
			Mask: net.CIDRMask(int(route.DstLength), 8*len(route.Attributes.Dst)),
		}
	}
	tableOfRoute := func(route *rtnetlink.RouteMessage) (table uint32) {
		table = route.Attributes.Table
		if table != 0 {
			return
		}
		table = uint32(route.Table)
		if table != 0 {
			return
		}
		table = unix.RT_TABLE_MAIN
		return
	}

	table := uint32(unix.RT_TABLE_MAIN)
	if c.Table != nil {
		table = *c.Table
	}

	oldRoutes := map[string]rtnetlink.RouteMessage{}
	{
		var oas []rtnetlink.RouteMessage
		oas, err = conn.Conn.Route.List()
		if err != nil {
			err = fmt.Errorf("failed to get old routes: %w", err)
			return
		}
		for _, oa := range oas {
			if oa.Protocol != unix.RTPROT_BOOT && oa.Protocol != unix.RTPROT_STATIC {
				// skip any routes added by kernel or any other routing daemons
				continue
			}
			if tableOfRoute(&oa) == table && oa.Attributes.OutIface == uint32(ifce.Index) {
				prefix := toIPNet(&oa)
				oldRoutes[prefix.String()] = oa
			}
		}
	}

	newRoutes := map[string]net.IPNet{}
	for _, na := range c.Routes {
		newRoutes[na.String()] = na
	}

routeDedupLoopOuter:
	for oak := range oldRoutes {
		for nak := range newRoutes {
			if oak == nak {
				// remove common elements, then oldRoutes will be the routes to delete,
				// and newRoutes will be the routes to add
				delete(oldRoutes, oak)
				delete(newRoutes, nak)
				continue routeDedupLoopOuter
			}
		}
	}

	for s, route := range oldRoutes {
		log.Printf("[#] ip route del %s dev %s table %d", s, c.Device, table)
		err = conn.Conn.Route.Delete(&route)
		if err != nil {
			err = fmt.Errorf("failed to delete old route %s on interface %s: %w", s, c.Device, err)
			return
		}
	}

	for s, route := range newRoutes {
		log.Printf("[#] ip route add %s dev %s table %d", s, c.Device, table)
		err = conn.RouteAdd(ifce, route, nil, func(ro *rtnl.RouteOptions) {
			ro.Attrs.Table = table
			ro.Attrs.OutIface = uint32(ifce.Index)
		})
		if err != nil {
			err = fmt.Errorf("failed to add new route %s on interface %s: %w", route.String(), c.Device, err)
			return
		}
	}

	return
}
