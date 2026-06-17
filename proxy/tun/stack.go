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
}
