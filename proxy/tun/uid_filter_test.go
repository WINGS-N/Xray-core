package tun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// uidFilterConn is what a connection of the stack looks like to the filter
type uidFilterConn struct {
	uid  int32
	src  netip.AddrPort
	dst  netip.AddrPort
	want uidDecision
}

func TestUIDFilterDecides(t *testing.T) {
	const (
		tunneled = 10
		excluded = 11
		bypassed = 12
		routed   = 13
	)
	cases := []struct {
		name   string
		config *Config
		conn   uidFilterConn
	}{
		{
			name:   "excluded uid is refused",
			config: &Config{ExcludedUids: []uint32{excluded}},
			conn:   uidFilterConn{uid: excluded, want: uidDecision{drop: true}},
		},
		{
			name:   "uid off the killlist tunnels",
			config: &Config{ExcludedUids: []uint32{excluded}},
			conn:   uidFilterConn{uid: tunneled, want: uidDecision{}},
		},
		{
			name:   "bypass uid takes the bypass inbound",
			config: &Config{BypassUids: []uint32{bypassed}, BypassInboundTag: "direct"},
			conn:   uidFilterConn{uid: bypassed, want: uidDecision{tag: "direct"}},
		},
		{
			name:   "allowlisted uid tunnels",
			config: &Config{AllowedUids: []uint32{tunneled}, BypassInboundTag: "direct"},
			conn:   uidFilterConn{uid: tunneled, want: uidDecision{}},
		},
		{
			name:   "uid off the allowlist goes out directly",
			config: &Config{AllowedUids: []uint32{tunneled}, BypassInboundTag: "direct"},
			conn:   uidFilterConn{uid: bypassed, want: uidDecision{tag: "direct"}},
		},
		{
			name:   "allowlist without a bypass inbound refuses the rest",
			config: &Config{AllowedUids: []uint32{tunneled}},
			conn:   uidFilterConn{uid: bypassed, want: uidDecision{drop: true}},
		},
		{
			name: "route uid wins over the allow decision",
			config: &Config{
				AllowedUids:      []uint32{tunneled},
				RouteUids:        []uint32{routed},
				BypassInboundTag: "direct",
				RouteInboundTag:  "byedpi",
			},
			conn: uidFilterConn{uid: routed, want: uidDecision{tag: "byedpi"}},
		},
		{
			name: "an excluded uid is refused even when it is routed",
			config: &Config{
				ExcludedUids:    []uint32{excluded},
				RouteUids:       []uint32{excluded},
				RouteInboundTag: "byedpi",
			},
			conn: uidFilterConn{uid: excluded, want: uidDecision{drop: true}},
		},
		{
			name: "unknown uid is refused while a bypass list is active",
			config: &Config{
				BypassUids:       []uint32{bypassed},
				BypassInboundTag: "direct",
			},
			conn: uidFilterConn{uid: -1, want: uidDecision{drop: true}},
		},
		{
			name: "unknown uid goes out directly when asked",
			config: &Config{
				BypassUids:       []uint32{bypassed},
				BypassInboundTag: "direct",
				BypassUnknownUid: true,
			},
			conn: uidFilterConn{uid: -1, want: uidDecision{tag: "direct"}},
		},
		{
			name: "unknown uid tunnels when asked, whatever else is set",
			config: &Config{
				BypassUids:       []uint32{bypassed},
				BypassInboundTag: "direct",
				BypassUnknownUid: true,
				TunnelUnknownUid: true,
			},
			conn: uidFilterConn{uid: -1, want: uidDecision{}},
		},
		{
			name:   "unknown uid tunnels under a killlist alone",
			config: &Config{ExcludedUids: []uint32{excluded}},
			conn:   uidFilterConn{uid: -1, want: uidDecision{}},
		},
	}

	// every case takes a port of its own: the lookup of a 4-tuple is cached
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := netip.MustParseAddrPort("10.0.0.2:0")
			src = netip.AddrPortFrom(src.Addr(), uint16(40000+i))
			dst := netip.MustParseAddrPort("93.184.216.34:443")
			SetUIDLookupCallback(func(_ int, gotSrc, gotDst netip.AddrPort) int32 {
				if gotSrc != src || gotDst != dst {
					t.Errorf("looked up %s -> %s, want %s -> %s", gotSrc, gotDst, src, dst)
				}
				return c.conn.uid
			})
			defer SetUIDLookupCallback(nil)

			filter := newUIDFilter(c.config)
			if filter == nil {
				t.Fatal("no filter was built of a config that lists uids")
			}
			if got := filter.decide(protoTCP, src, dst); got != c.conn.want {
				t.Fatalf("decided %+v, want %+v", got, c.conn.want)
			}
		})
	}
}

func TestUIDFilterTakesNoListAsNoFilter(t *testing.T) {
	if filter := newUIDFilter(&Config{BypassInboundTag: "direct"}); filter != nil {
		t.Fatal("a filter was built of a config that lists no uid")
	}
}

func TestUIDFilterStampIsTakenOnce(t *testing.T) {
	filter := newUIDFilter(&Config{BypassUids: []uint32{12}, BypassInboundTag: "direct"})
	source := net.TCPDestination(net.ParseAddress("10.0.0.2"), 40100)
	filter.stamp(source, "direct")
	if got := filter.tagFor(source); got != "direct" {
		t.Fatalf("the stamped tag is %q, want %q", got, "direct")
	}
	if got := filter.tagFor(source); got != "" {
		t.Fatalf("the tag is still %q after it was taken", got)
	}
	filter.stamp(source, "direct")
	filter.stamp(source, "")
	if got := filter.tagFor(source); got != "" {
		t.Fatalf("the tag is %q after it was given up", got)
	}
}

func TestUIDFilterCachesTheDecisionOfAFlow(t *testing.T) {
	src := netip.MustParseAddrPort("10.0.0.2:40200")
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	lookups := 0
	SetUIDLookupCallback(func(_ int, _, _ netip.AddrPort) int32 {
		lookups++
		return 12
	})
	defer SetUIDLookupCallback(nil)

	filter := newUIDFilter(&Config{BypassUids: []uint32{12}, BypassInboundTag: "direct"})
	for range 3 {
		if got := filter.decide(protoUDP, src, dst); got.tag != "direct" {
			t.Fatalf("decided %+v, want the bypass inbound", got)
		}
	}
	if lookups != 1 {
		t.Fatalf("the owner was looked up %d times, want 1", lookups)
	}
}

// newUIDStack is the stack of the tests with a filter of its own
func newUIDStack(t *testing.T, l *link, handle func(net.Conn, net.Destination), config *Config) *stack {
	s := &stack{
		ctx: context.Background(), tun: l, mtu: testMTU, window: tcpWindow, handle: handle,
		conns: make(map[flow]*tcpConn), sockets: make(map[netip.AddrPort]*udpSocket),
		uid: newUIDFilter(config),
	}
	if handle != nil {
		s.udp = newUdpConnectionHandler(handle, s.writeUDP)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		l.Close()
	})
	return s
}

// What an excluded app opens is reset, and no connection of it is handed over.
func TestStackRefusesWhatAnExcludedUIDOpens(t *testing.T) {
	SetUIDLookupCallback(func(_ int, _, _ netip.AddrPort) int32 { return 11 })
	defer SetUIDLookupCallback(nil)

	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:80")
	newUIDStack(t, l, accept(conns), &Config{ExcludedUids: []uint32{11}})

	p.send(p.seq, tcpSyn, nil, nil)
	if s := p.receive(); s.flags != tcpRst|tcpAck {
		t.Fatal("the SYN was answered with flags ", s.flags, ", want a reset")
	}
	p.silent(50 * time.Millisecond)
	select {
	case a := <-conns:
		t.Fatal("a connection from ", a.conn.RemoteAddr(), " was handed over")
	default:
	}
}

// What a bypassed app opens is handed over with an inbound tag of its own.
func TestStackStampsWhatABypassedUIDOpens(t *testing.T) {
	SetUIDLookupCallback(func(_ int, _, _ netip.AddrPort) int32 { return 12 })
	defer SetUIDLookupCallback(nil)

	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1235", "10.0.0.2:80")
	s := newUIDStack(t, l, accept(conns), &Config{BypassUids: []uint32{12}, BypassInboundTag: "direct"})

	p.connect(nil)
	a := take(t, conns)
	source := net.DestinationFromAddr(a.conn.RemoteAddr())
	if tag := s.uid.tagFor(source); tag != "direct" {
		t.Fatalf("the connection of %s carries the tag %q, want %q", source, tag, "direct")
	}
}

// Nothing is answered to the UDP of an excluded app, and none of it is handed over.
func TestStackDropsTheUDPOfAnExcludedUID(t *testing.T) {
	SetUIDLookupCallback(func(_ int, _, _ netip.AddrPort) int32 { return 11 })
	defer SetUIDLookupCallback(nil)

	conns := make(chan accepted, 1)
	p, l := newPeer(t, "10.0.0.1:1236", "10.0.0.2:53")
	newUIDStack(t, l, accept(conns), &Config{ExcludedUids: []uint32{11}})

	l.in <- summed(udpPacket(p.src, p.dst, []byte("abc")))
	p.silent(50 * time.Millisecond)
	select {
	case a := <-conns:
		t.Fatal("a connection from ", a.conn.RemoteAddr(), " was handed over")
	default:
	}
}
