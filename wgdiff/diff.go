package wgdiff

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

func CalcDiff(current *wgtypes.Device, desired *wgtypes.Config) (diff *wgtypes.Config, err error) {
	if current == nil {
		diff = desired
		return
	}

	diff = &wgtypes.Config{}

	diff.PrivateKey = desired.PrivateKey
	diff.ListenPort = desired.ListenPort
	diff.FirewallMark = desired.FirewallMark

	// do not use ReplacePeers as it actually removes all peers first and reset all status.

	oldPeers := make(map[wgtypes.Key]*wgtypes.Peer, len(current.Peers))
	for i := range current.Peers {
		oldPeers[current.Peers[i].PublicKey] = &current.Peers[i]
	}
	newPeers := desired.Peers
	// we only need to find the deleted peers
	// all peers that are not intended to be deleted can be updated seamlessly
	for _, peer := range newPeers {
		delete(oldPeers, peer.PublicKey)
	}
	// now the oldPeers only contains the peers to be deleted

	diff.Peers = make([]wgtypes.PeerConfig, 0, len(oldPeers)+len(newPeers))
	diff.Peers = append(diff.Peers, newPeers...)
	for _, peer := range oldPeers {
		diff.Peers = append(diff.Peers, wgtypes.PeerConfig{
			PublicKey: peer.PublicKey,
			Remove:    true,
		})
	}

	return
}
