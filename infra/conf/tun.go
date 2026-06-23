package conf

import (
	"github.com/xtls/xray-core/proxy/tun"
	"google.golang.org/protobuf/proto"
)

type TunConfig struct {
	Name                   string   `json:"name"`
	MTU                    uint32   `json:"mtu"`
	Gateway                []string `json:"gateway"`
	DNS                    []string `json:"dns"`
	UserLevel              uint32   `json:"userLevel"`
	AutoSystemRoutingTable []string `json:"autoSystemRoutingTable"`
	AutoOutboundsInterface *string  `json:"autoOutboundsInterface"`
	ExcludedUIDs           []uint32 `json:"excludedUids"`
	AllowedUIDs            []uint32 `json:"allowedUids"`
	BypassUIDs             []uint32 `json:"bypassUids"`
	BypassInboundTag       string   `json:"bypassInboundTag"`
	BypassUnknownUID       bool     `json:"bypassUnknownUid"`
	TunnelUnknownUID       bool     `json:"tunnelUnknownUid"`
	UIDLookupTimeoutMs     uint32   `json:"uidLookupTimeoutMs"`
}

func (v *TunConfig) Build() (proto.Message, error) {
	config := &tun.Config{
		Name:                   v.Name,
		MTU:                    v.MTU,
		Gateway:                v.Gateway,
		DNS:                    v.DNS,
		UserLevel:              v.UserLevel,
		AutoSystemRoutingTable: v.AutoSystemRoutingTable,
		ExcludedUids:           v.ExcludedUIDs,
		AllowedUids:            v.AllowedUIDs,
		BypassUids:             v.BypassUIDs,
		BypassInboundTag:       v.BypassInboundTag,
		BypassUnknownUid:       v.BypassUnknownUID,
		TunnelUnknownUid:       v.TunnelUnknownUID,
		UidLookupTimeoutMs:     v.UIDLookupTimeoutMs,
	}
	if v.AutoOutboundsInterface != nil {
		config.AutoOutboundsInterface = *v.AutoOutboundsInterface
	}
	if len(v.AutoSystemRoutingTable) > 0 && v.AutoOutboundsInterface == nil {
		config.AutoOutboundsInterface = "auto"
	}

	if config.Name == "" {
		config.Name = "xray0"
	}
	if config.MTU == 0 {
		config.MTU = 1500
	}
	return config, nil
}
