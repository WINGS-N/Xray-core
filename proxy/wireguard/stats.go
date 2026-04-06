package wireguard

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const wireGuardTrafficStatPrefix = "wireguard"

type PeerStatSnapshot struct {
	PublicKey         string
	ReceiveBytes      int64
	TransmitBytes     int64
	LastHandshakeTime time.Time
}

type DynamicStat struct {
	Name  string
	Value int64
}

type peerStatsProvider interface {
	PeerStats() ([]PeerStatSnapshot, error)
}

type peerStatsRegistry struct {
	mu        sync.RWMutex
	providers map[string]peerStatsProvider
	baselines map[string]int64
}

var wireGuardPeerStatsRegistry = &peerStatsRegistry{
	providers: make(map[string]peerStatsProvider),
	baselines: make(map[string]int64),
}

func registerPeerStatsProvider(tag string, provider peerStatsProvider) {
	tag = strings.TrimSpace(tag)
	if tag == "" || provider == nil {
		return
	}

	wireGuardPeerStatsRegistry.mu.Lock()
	defer wireGuardPeerStatsRegistry.mu.Unlock()
	wireGuardPeerStatsRegistry.providers[tag] = provider
}

func unregisterPeerStatsProvider(tag string, provider peerStatsProvider) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return
	}

	wireGuardPeerStatsRegistry.mu.Lock()
	defer wireGuardPeerStatsRegistry.mu.Unlock()

	current, ok := wireGuardPeerStatsRegistry.providers[tag]
	if !ok {
		return
	}
	if provider != nil && current != provider {
		return
	}

	delete(wireGuardPeerStatsRegistry.providers, tag)

	prefix := wireGuardTrafficStatPrefix + ">>>" + tag + ">>>"
	for name := range wireGuardPeerStatsRegistry.baselines {
		if strings.HasPrefix(name, prefix) {
			delete(wireGuardPeerStatsRegistry.baselines, name)
		}
	}
}

func GetWireGuardStat(name string, reset bool) (*DynamicStat, bool, error) {
	tag, publicKey, direction, ok := parseWireGuardTrafficStatName(name)
	if !ok {
		return nil, false, nil
	}

	provider := wireGuardPeerStatsRegistry.getProvider(tag)
	if provider == nil {
		return nil, false, nil
	}

	peers, err := provider.PeerStats()
	if err != nil {
		return nil, true, err
	}

	for _, peer := range peers {
		if peer.PublicKey != publicKey {
			continue
		}

		current := peerTrafficBytes(peer, direction)
		return &DynamicStat{
			Name:  name,
			Value: wireGuardPeerStatsRegistry.valueForCounter(name, current, reset),
		}, true, nil
	}

	return nil, false, nil
}

func QueryWireGuardStats(pattern string, reset bool) ([]*DynamicStat, error) {
	providers := wireGuardPeerStatsRegistry.snapshotProviders()
	response := make([]*DynamicStat, 0)

	for _, item := range providers {
		peers, err := item.provider.PeerStats()
		if err != nil {
			errors.LogDebug(context.Background(), "skip wireguard stats for inbound ", item.tag, ": ", err)
			continue
		}

		sort.Slice(peers, func(i, j int) bool {
			return peers[i].PublicKey < peers[j].PublicKey
		})

		for _, peer := range peers {
			uplinkName := buildWireGuardTrafficStatName(item.tag, peer.PublicKey, "uplink")
			if pattern == "" || strings.Contains(uplinkName, pattern) {
				response = append(response, &DynamicStat{
					Name:  uplinkName,
					Value: wireGuardPeerStatsRegistry.valueForCounter(uplinkName, peer.ReceiveBytes, reset),
				})
			}

			downlinkName := buildWireGuardTrafficStatName(item.tag, peer.PublicKey, "downlink")
			if pattern == "" || strings.Contains(downlinkName, pattern) {
				response = append(response, &DynamicStat{
					Name:  downlinkName,
					Value: wireGuardPeerStatsRegistry.valueForCounter(downlinkName, peer.TransmitBytes, reset),
				})
			}
		}
	}

	sort.Slice(response, func(i, j int) bool {
		return response[i].Name < response[j].Name
	})
	return response, nil
}

type taggedPeerStatsProvider struct {
	tag      string
	provider peerStatsProvider
}

func (r *peerStatsRegistry) getProvider(tag string) peerStatsProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.providers[tag]
}

func (r *peerStatsRegistry) snapshotProviders() []taggedPeerStatsProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	items := make([]taggedPeerStatsProvider, 0, len(r.providers))
	for tag, provider := range r.providers {
		items = append(items, taggedPeerStatsProvider{
			tag:      tag,
			provider: provider,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].tag < items[j].tag
	})

	return items
}

func (r *peerStatsRegistry) valueForCounter(name string, current int64, reset bool) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	baseline := r.baselines[name]
	if current < baseline {
		baseline = 0
	}

	value := current - baseline
	if reset {
		r.baselines[name] = current
	}

	return value
}

func buildWireGuardTrafficStatName(tag string, publicKey string, direction string) string {
	return strings.Join([]string{
		wireGuardTrafficStatPrefix,
		tag,
		publicKey,
		"traffic",
		direction,
	}, ">>>")
}

func parseWireGuardTrafficStatName(name string) (tag string, publicKey string, direction string, ok bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 5 {
		return "", "", "", false
	}
	if parts[0] != wireGuardTrafficStatPrefix || parts[3] != "traffic" {
		return "", "", "", false
	}
	if parts[4] != "uplink" && parts[4] != "downlink" {
		return "", "", "", false
	}
	if strings.TrimSpace(parts[1]) == "" || strings.TrimSpace(parts[2]) == "" {
		return "", "", "", false
	}
	return parts[1], parts[2], parts[4], true
}

func peerTrafficBytes(peer PeerStatSnapshot, direction string) int64 {
	switch direction {
	case "uplink":
		return peer.ReceiveBytes
	case "downlink":
		return peer.TransmitBytes
	default:
		return 0
	}
}

func parsePeerStatsIPC(raw string) ([]PeerStatSnapshot, error) {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	peers := make([]PeerStatSnapshot, 0)

	var current *PeerStatSnapshot
	var handshakeSec int64
	var handshakeNsec int64

	flush := func() {
		if current == nil || current.PublicKey == "" {
			return
		}
		if handshakeSec != 0 || handshakeNsec != 0 {
			current.LastHandshakeTime = time.Unix(handshakeSec, handshakeNsec).UTC()
		}
		peers = append(peers, *current)
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		switch key {
		case "public_key":
			flush()

			publicKey, err := wireGuardHexKeyToBase64(value)
			if err != nil {
				return nil, err
			}

			current = &PeerStatSnapshot{PublicKey: publicKey}
			handshakeSec = 0
			handshakeNsec = 0
		case "rx_bytes":
			if current == nil {
				continue
			}
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, err
			}
			current.ReceiveBytes = parsed
		case "tx_bytes":
			if current == nil {
				continue
			}
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, err
			}
			current.TransmitBytes = parsed
		case "last_handshake_time_sec":
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, err
			}
			handshakeSec = parsed
		case "last_handshake_time_nsec":
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, err
			}
			handshakeNsec = parsed
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	flush()
	return peers, nil
}

func wireGuardHexKeyToBase64(raw string) (string, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}
