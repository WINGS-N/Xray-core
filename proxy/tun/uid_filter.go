package tun

import (
	"net/netip"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// uidDecision is the outcome of the per-connection UID lookup. drop means the
// stack refuses the connection (a RST for TCP, silence for UDP). tag is the
// inbound tag to stamp on it, empty meaning the handler's default tag.
type uidDecision struct {
	drop bool
	tag  string
}

const (
	// uidLookupRetryInterval is how often the /proc/net table is polled again
	// while the lookup window of the config has not elapsed
	uidLookupRetryInterval = 5 * time.Millisecond
	// uidDecisionTTL is how long a decision of a 4-tuple is reused. A UID does
	// not change under a live connection, and a port that comes back is a new
	// tuple only once its peer differs, so the window is only about dropping
	// what is gone
	uidDecisionTTL = 30 * time.Second
	// uidDecisionLimit and uidTagLimit are when what has expired is swept
	uidDecisionLimit = 4096
	uidTagLimit      = 512
)

// uidFilter decides what happens to a connection by the UID that owns it: the
// tunnel, a RST, or an inbound tag of its own. Android needs it because
// VpnService only steers routing - an app that is left out of the tunnel can
// still bind the TUN itself - and because a non-root VpnService sees the UID
// of a connection through ConnectivityManager alone, which the stack reaches
// via the lookup callback.
type uidFilter struct {
	excluded map[uint32]struct{}
	allowed  map[uint32]struct{}
	bypass   map[uint32]struct{}
	route    map[uint32]struct{}

	bypassInboundTag string
	routeInboundTag  string
	bypassUnknownUID bool
	tunnelUnknownUID bool
	lookupTimeout    time.Duration

	mu sync.Mutex
	// decisions are the outcomes of the lookups of the 4-tuples that are live
	decisions map[uidFlow]uidDecisionEntry
	// tags are the inbound tags of the connections that wait for their handler,
	// which takes them by the source that the connection carries
	tags map[net.Destination]uidTagEntry
}

// uidFlow is a 4-tuple of one direction, src being the side of the system
type uidFlow struct {
	proto    uint8
	src, dst netip.AddrPort
}

type uidDecisionEntry struct {
	decision uidDecision
	at       time.Time
}

type uidTagEntry struct {
	tag string
	at  time.Time
}

// newUIDFilter builds the filter of a config, or nothing if no list is set
func newUIDFilter(config *Config) *uidFilter {
	if len(config.ExcludedUids) == 0 && len(config.AllowedUids) == 0 &&
		len(config.BypassUids) == 0 && len(config.RouteUids) == 0 {
		return nil
	}
	return &uidFilter{
		excluded:         uidSet(config.ExcludedUids),
		allowed:          uidSet(config.AllowedUids),
		bypass:           uidSet(config.BypassUids),
		route:            uidSet(config.RouteUids),
		bypassInboundTag: config.BypassInboundTag,
		routeInboundTag:  config.RouteInboundTag,
		bypassUnknownUID: config.BypassUnknownUid,
		tunnelUnknownUID: config.TunnelUnknownUid,
		lookupTimeout:    time.Duration(config.UidLookupTimeoutMs) * time.Millisecond,
		decisions:        make(map[uidFlow]uidDecisionEntry),
		tags:             make(map[net.Destination]uidTagEntry),
	}
}

func uidSet(uids []uint32) map[uint32]struct{} {
	if len(uids) == 0 {
		return nil
	}
	set := make(map[uint32]struct{}, len(uids))
	for _, uid := range uids {
		set[uid] = struct{}{}
	}
	return set
}

// decide resolves what to do with the connection of a 4-tuple. src is the
// TUN side, the app's own endpoint, dst the one it reaches for. The outcome is
// kept for a while: UDP asks for every packet of a flow, and a lookup that
// misses costs the whole retry window
func (f *uidFilter) decide(proto uint8, src, dst netip.AddrPort) uidDecision {
	flow := uidFlow{proto: proto, src: src, dst: dst}
	if decision, ok := f.cached(flow); ok {
		return decision
	}
	decision := f.resolve(proto, src, dst)
	f.remember(flow, decision)
	return decision
}

func (f *uidFilter) resolve(proto uint8, src, dst netip.AddrPort) uidDecision {
	uid := f.lookupWithRetry(proto, src, dst)
	if uid < 0 {
		// The UID is unknown: Android did not see this connection, which is
		// what a socket bound to the TUN itself looks like (curl --interface
		// tun0 and the like), side-stepping the per-app tracker.
		//
		// tunnelUnknownUID: the caller asked for those to tunnel as any other.
		// bypassUnknownUID: send them out directly instead. Neither, with a
		// bypass or allow list active: drop, or the app whose traffic was to
		// stay off the VPN leaks into it through this very hole. A killlist
		// alone is not affected - there "unknown" only means "not on it"
		if f.tunnelUnknownUID {
			return uidDecision{}
		}
		if f.bypassUnknownUID && f.bypassInboundTag != "" {
			return uidDecision{tag: f.bypassInboundTag}
		}
		if !f.bypassUnknownUID && (len(f.bypass) > 0 || len(f.allowed) > 0) {
			return uidDecision{drop: true}
		}
		return uidDecision{}
	}
	if _, blocked := f.excluded[uint32(uid)]; blocked {
		return uidDecision{drop: true}
	}
	// A route UID wins over the allow and bypass decision, an excluded one
	// still kills it: routing sends those apps to an outbound of their own
	// whatever the app-routing mode is
	if f.routeInboundTag != "" {
		if _, routed := f.route[uint32(uid)]; routed {
			return uidDecision{tag: f.routeInboundTag}
		}
	}
	if len(f.allowed) > 0 {
		if _, allowed := f.allowed[uint32(uid)]; !allowed {
			// Not on the allowlist. With a bypass inbound the connection goes
			// out directly instead of being refused, so that the apps that
			// were not picked keep working off the tunnel
			if f.bypassInboundTag != "" {
				return uidDecision{tag: f.bypassInboundTag}
			}
			return uidDecision{drop: true}
		}
	}
	if _, bypass := f.bypass[uint32(uid)]; bypass {
		return uidDecision{tag: f.bypassInboundTag}
	}
	return uidDecision{}
}

// lookupWithRetry polls for the owner of the connection until the window of
// the config has elapsed. An app that opens sockets one after another sends
// its SYN through the TUN before the kernel has published the socket, and a
// strict filter would refuse what is in fact its own traffic
func (f *uidFilter) lookupWithRetry(proto uint8, src, dst netip.AddrPort) int32 {
	uid := lookupConnectionUID(int(proto), src.Addr(), src.Port(), dst.Addr(), dst.Port())
	if uid >= 0 || f.lookupTimeout <= 0 {
		return uid
	}
	deadline := time.Now().Add(f.lookupTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return uid
		}
		time.Sleep(min(uidLookupRetryInterval, remaining))
		if uid = lookupConnectionUID(int(proto), src.Addr(), src.Port(), dst.Addr(), dst.Port()); uid >= 0 {
			return uid
		}
	}
}

func (f *uidFilter) cached(flow uidFlow) (uidDecision, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.decisions[flow]
	if !ok || time.Since(entry.at) > uidDecisionTTL {
		return uidDecision{}, false
	}
	return entry.decision, true
}

func (f *uidFilter) remember(flow uidFlow, decision uidDecision) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.decisions) >= uidDecisionLimit {
		for key, entry := range f.decisions {
			if time.Since(entry.at) > uidDecisionTTL {
				delete(f.decisions, key)
			}
		}
	}
	f.decisions[flow] = uidDecisionEntry{decision: decision, at: time.Now()}
}

// stamp leaves the inbound tag of a connection for its handler to find. An
// empty tag forgets what the source had, or a connection that opens on a port
// that another app has just given up would take over its tag
func (f *uidFilter) stamp(source net.Destination, tag string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if tag == "" {
		delete(f.tags, source)
		return
	}
	if len(f.tags) >= uidTagLimit {
		for key, entry := range f.tags {
			if time.Since(entry.at) > uidDecisionTTL {
				delete(f.tags, key)
			}
		}
	}
	f.tags[source] = uidTagEntry{tag: tag, at: time.Now()}
}

// tagFor returns the inbound tag that the stack stamped on the connection of
// a source, empty if it is to take the default one
func (f *uidFilter) tagFor(source net.Destination) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.tags[source]
	if !ok {
		return ""
	}
	delete(f.tags, source)
	return entry.tag
}
