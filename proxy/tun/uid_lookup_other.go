//go:build !linux

package tun

import "net/netip"

// lookupConnectionUID is a no-op outside Linux/Android. The TUN excluded-UID
// filter only makes sense on Android where the gVisor stack sits behind the
// kernel TUN driver and can be re-entered by apps that side-step Android's
// addDisallowedApplication routing rules.
func lookupConnectionUID(_ int, _ netip.Addr, _ uint16, _ netip.Addr, _ uint16) int32 {
	return -1
}
