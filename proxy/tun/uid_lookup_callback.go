package tun

import (
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
)

var (
	uidLookupDiagCount atomic.Int64
	uidLookupDiagPath  atomic.Pointer[string]
)

// SetUIDLookupDiagPath registers a writable file path that the lookup callback
// appends diagnostics to. Bypasses Android's stderr suppression for SDK apps;
// the path is typically inside the app's filesDir so the package can read it
// back via run-as. Empty string disables file diag.
func SetUIDLookupDiagPath(p string) {
	if p == "" {
		uidLookupDiagPath.Store(nil)
		return
	}
	uidLookupDiagPath.Store(&p)
}

func uidDiagWrite(format string, args ...any) {
	pp := uidLookupDiagPath.Load()
	if pp == nil {
		return
	}
	f, err := os.OpenFile(*pp, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format, args...)
}

// UIDLookupCallback resolves the local UID that owns a connection identified by
// its 5-tuple. Returns -1 when the lookup fails or the connection is unknown.
//
// On Android, the implementation is expected to wrap
// ConnectivityManager.getConnectionOwnerUid() via JNI - the only API that lets
// a non-root VPN app see the UID of connections routed through its tunnel.
// /proc/net/tcp is SELinux-blocked for untrusted_app and NETLINK_INET_DIAG is
// blocked by sepolicy neverallow, leaving this API as the only viable signal.
//
// On non-Android Linux (TPROXY mode, root daemon), this stays nil and the
// caller falls back to scanning /proc/net/tcp* directly.
type UIDLookupCallback func(protocol int, src netip.AddrPort, dst netip.AddrPort) int32

var (
	uidLookupCallbackMu sync.RWMutex
	uidLookupCallback   UIDLookupCallback
)

// SetUIDLookupCallback installs an external resolver. Pass nil to clear.
func SetUIDLookupCallback(cb UIDLookupCallback) {
	uidLookupCallbackMu.Lock()
	uidLookupCallback = cb
	uidLookupCallbackMu.Unlock()
	uidDiagWrite("[uid-diag-go] SetUIDLookupCallback nil=%v\n", cb == nil)
}

func getUIDLookupCallback() UIDLookupCallback {
	uidLookupCallbackMu.RLock()
	cb := uidLookupCallback
	uidLookupCallbackMu.RUnlock()
	return cb
}
