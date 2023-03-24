package wgconf

type NetworkConfig interface {
	ApplyNetworkConfig() error
}
