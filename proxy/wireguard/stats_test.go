package wireguard

import (
	"encoding/base64"
	"testing"
	"time"
)

type staticPeerStatsProvider struct {
	peers []PeerStatSnapshot
	err   error
}

func (p *staticPeerStatsProvider) PeerStats() ([]PeerStatSnapshot, error) {
	if p.err != nil {
		return nil, p.err
	}

	out := make([]PeerStatSnapshot, len(p.peers))
	copy(out, p.peers)
	return out, nil
}

func resetWireGuardPeerStatsRegistryForTest() {
	wireGuardPeerStatsRegistry.mu.Lock()
	defer wireGuardPeerStatsRegistry.mu.Unlock()
	wireGuardPeerStatsRegistry.providers = make(map[string]peerStatsProvider)
	wireGuardPeerStatsRegistry.baselines = make(map[string]int64)
}

func testWireGuardPublicKey(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestParsePeerStatsIPC(t *testing.T) {
	raw := "" +
		"private_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
		"public_key=0101010101010101010101010101010101010101010101010101010101010101\n" +
		"last_handshake_time_sec=10\n" +
		"last_handshake_time_nsec=20\n" +
		"tx_bytes=30\n" +
		"rx_bytes=40\n"

	peers, err := parsePeerStatsIPC(raw)
	if err != nil {
		t.Fatalf("parsePeerStatsIPC() error = %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("parsePeerStatsIPC() peers = %d, want 1", len(peers))
	}

	wantKey := testWireGuardPublicKey(0x01)
	if peers[0].PublicKey != wantKey {
		t.Fatalf("PublicKey = %q, want %q", peers[0].PublicKey, wantKey)
	}
	if peers[0].TransmitBytes != 30 {
		t.Fatalf("TransmitBytes = %d, want 30", peers[0].TransmitBytes)
	}
	if peers[0].ReceiveBytes != 40 {
		t.Fatalf("ReceiveBytes = %d, want 40", peers[0].ReceiveBytes)
	}

	wantHandshake := time.Unix(10, 20).UTC()
	if !peers[0].LastHandshakeTime.Equal(wantHandshake) {
		t.Fatalf("LastHandshakeTime = %v, want %v", peers[0].LastHandshakeTime, wantHandshake)
	}
}

func TestGetWireGuardStatResetAndRestart(t *testing.T) {
	resetWireGuardPeerStatsRegistryForTest()
	defer resetWireGuardPeerStatsRegistryForTest()

	publicKey := testWireGuardPublicKey(0x02)
	provider := &staticPeerStatsProvider{
		peers: []PeerStatSnapshot{{
			PublicKey:     publicKey,
			ReceiveBytes:  12,
			TransmitBytes: 20,
		}},
	}
	registerPeerStatsProvider("wg-inbound", provider)

	downlinkName := buildWireGuardTrafficStatName("wg-inbound", publicKey, "downlink")

	stat, ok, err := GetWireGuardStat(downlinkName, true)
	if err != nil || !ok {
		t.Fatalf("GetWireGuardStat(reset=true) ok=%t err=%v", ok, err)
	}
	if stat.Value != 20 {
		t.Fatalf("GetWireGuardStat(reset=true) value = %d, want 20", stat.Value)
	}

	stat, ok, err = GetWireGuardStat(downlinkName, false)
	if err != nil || !ok {
		t.Fatalf("GetWireGuardStat(reset=false) ok=%t err=%v", ok, err)
	}
	if stat.Value != 0 {
		t.Fatalf("GetWireGuardStat(after reset) value = %d, want 0", stat.Value)
	}

	provider.peers[0].TransmitBytes = 35
	stat, ok, err = GetWireGuardStat(downlinkName, false)
	if err != nil || !ok {
		t.Fatalf("GetWireGuardStat(after growth) ok=%t err=%v", ok, err)
	}
	if stat.Value != 15 {
		t.Fatalf("GetWireGuardStat(after growth) value = %d, want 15", stat.Value)
	}

	provider.peers[0].TransmitBytes = 5
	stat, ok, err = GetWireGuardStat(downlinkName, false)
	if err != nil || !ok {
		t.Fatalf("GetWireGuardStat(after restart) ok=%t err=%v", ok, err)
	}
	if stat.Value != 5 {
		t.Fatalf("GetWireGuardStat(after restart) value = %d, want 5", stat.Value)
	}
}

func TestQueryWireGuardStatsPattern(t *testing.T) {
	resetWireGuardPeerStatsRegistryForTest()
	defer resetWireGuardPeerStatsRegistryForTest()

	publicKey := testWireGuardPublicKey(0x03)
	registerPeerStatsProvider("wg-inbound", &staticPeerStatsProvider{
		peers: []PeerStatSnapshot{{
			PublicKey:     publicKey,
			ReceiveBytes:  7,
			TransmitBytes: 9,
		}},
	})

	stats, err := QueryWireGuardStats("traffic>>>uplink", false)
	if err != nil {
		t.Fatalf("QueryWireGuardStats() error = %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("QueryWireGuardStats() stats = %d, want 1", len(stats))
	}

	wantName := buildWireGuardTrafficStatName("wg-inbound", publicKey, "uplink")
	if stats[0].Name != wantName {
		t.Fatalf("QueryWireGuardStats() name = %q, want %q", stats[0].Name, wantName)
	}
	if stats[0].Value != 7 {
		t.Fatalf("QueryWireGuardStats() value = %d, want 7", stats[0].Value)
	}
}
