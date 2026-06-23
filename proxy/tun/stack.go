package tun

import (
	"time"
)

// Stack interface implement ip protocol stack, bridging raw network packets and data streams
type Stack interface {
	Start() error
	Close() error
}

// StackOptions for the stack implementation
type StackOptions struct {
	Tun         Tun
	IdleTimeout time.Duration
	// ExcludedUIDs is the set of Android UIDs whose new TCP/UDP connections
	// must be dropped before being dispatched. nil means no exclusion.
	// Membership is checked at connection setup time via /proc/net/* lookup
	// of the packet's source 4-tuple.
	ExcludedUIDs map[uint32]struct{}
	// AllowedUIDs, when non-empty, restricts the tunnel to those UIDs only;
	// any other UID is dropped. nil/empty means no allowlist gating.
	// ExcludedUIDs is checked first and takes precedence.
	AllowedUIDs map[uint32]struct{}
	// UIDLookupTimeout is the grace window for retrying the /proc/net UID
	// lookup when the first probe misses. New sockets that the kernel has
	// not yet published in /proc/net/tcp* (Tor / SSH opening multiple
	// sockets per second) would otherwise be dropped by the per-app filter.
	// Zero disables retries entirely; a single lookup is always performed.
	UIDLookupTimeout time.Duration
	// BypassUIDs holds UIDs whose connections are dispatched with
	// BypassInboundTag instead of the regular tun inbound tag. The routing
	// engine can then steer them to a freedom/direct outbound, which is the
	// non-root Android leak fix: keep the per-app VPN routing wide open so
	// ConnectivityManager.getConnectionOwnerUid can observe these apps, then
	// redirect them back to the underlying network at gVisor level.
	BypassUIDs map[uint32]struct{}
	// BypassInboundTag overrides the inbound Tag passed downstream when the
	// connection's source UID is in BypassUIDs. Empty means no override even
	// if BypassUIDs is set; the lookup is performed but the tag stays the
	// default, which is a useful diagnostic-only mode.
	BypassInboundTag string
	// BypassUnknownUID extends the bypass redirect to connections whose UID
	// resolution returned <0 (Android's getConnectionOwnerUid returns
	// INVALID_UID for sockets that bound directly to the TUN address and
	// thus skipped per-app VPN tracking). Effective only when
	// BypassInboundTag is set.
	BypassUnknownUID bool
	// TunnelUnknownUID lets connections whose UID could not be resolved fall
	// through to the default tunnel handler even when a bypass/allow list is
	// active, instead of being dropped or bypassed. Takes precedence over
	// BypassUnknownUID.
	TunnelUnknownUID bool
}
