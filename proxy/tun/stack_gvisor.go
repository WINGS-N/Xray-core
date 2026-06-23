package tun

import (
	"context"
	"net/netip"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	defaultNIC tcpip.NICID = 1

	tcpRXBufMinSize = tcp.MinBufferSize
	tcpRXBufDefSize = tcp.DefaultSendBufferSize
	tcpRXBufMaxSize = 8 << 20 // 8MiB

	tcpTXBufMinSize = tcp.MinBufferSize
	tcpTXBufDefSize = tcp.DefaultReceiveBufferSize
	tcpTXBufMaxSize = 6 << 20 // 6MiB
)

// stackGVisor is ip stack implemented by gVisor package
type stackGVisor struct {
	ctx              context.Context
	tun              Tun
	idleTimeout      time.Duration
	handler          *Handler
	stack            *stack.Stack
	endpoint         stack.LinkEndpoint
	excludedUIDs     map[uint32]struct{}
	allowedUIDs      map[uint32]struct{}
	bypassUIDs       map[uint32]struct{}
	bypassInboundTag string
	bypassUnknownUID bool
	tunnelUnknownUID bool
	uidLookupTimeout time.Duration
}

// NewStack builds new ip stack (using gVisor)
func NewStack(ctx context.Context, options StackOptions, handler *Handler) (Stack, error) {
	gStack := &stackGVisor{
		ctx:              ctx,
		tun:              options.Tun,
		idleTimeout:      options.IdleTimeout,
		handler:          handler,
		excludedUIDs:     options.ExcludedUIDs,
		allowedUIDs:      options.AllowedUIDs,
		bypassUIDs:       options.BypassUIDs,
		bypassInboundTag: options.BypassInboundTag,
		bypassUnknownUID: options.BypassUnknownUID,
		tunnelUnknownUID: options.TunnelUnknownUID,
		uidLookupTimeout: options.UIDLookupTimeout,
	}

	return gStack, nil
}

// isFilteredSource returns true when the packet's source 4-tuple belongs to a
// UID that is either explicitly excluded or, when an allowlist is configured,
// not present in it. srcAddr/srcPort describe the TUN-side (app's local)
// endpoint; dstAddr/dstPort describe the gVisor-side (app's remote) endpoint.
// Returns false on empty filters or when the UID cannot be looked up after
// the lookup retry window expires — Android's SELinux policy hides other
// apps' /proc/net/tcp* entries from the calling process unless it runs as
// root, so a strict drop on uid<0 would kill the entire tunnel under an
// unprivileged VpnService. The retry pass (uidLookupTimeout) is kept so
// that on platforms where the lookup does work (root TPROXY mode) it can
// absorb the /proc/net publication race for apps that open sockets in
// rapid succession.
// uidDecision holds the outcome of the per-connection UID lookup. drop=true
// means the gVisor stack should silently refuse the connection (RST for TCP,
// no reply for UDP). When drop=false the returned tag is the inbound Tag to
// pass downstream; empty means "use the handler's default tag".
type uidDecision struct {
	drop bool
	tag  string
}

func (t *stackGVisor) resolveUIDDecision(protocol int, srcAddr tcpip.Address, srcPort uint16, dstAddr tcpip.Address, dstPort uint16) uidDecision {
	if len(t.excludedUIDs) == 0 && len(t.allowedUIDs) == 0 && len(t.bypassUIDs) == 0 {
		return uidDecision{}
	}
	src, ok := netip.AddrFromSlice(srcAddr.AsSlice())
	if !ok {
		return uidDecision{}
	}
	dst, ok := netip.AddrFromSlice(dstAddr.AsSlice())
	if !ok {
		return uidDecision{}
	}
	uid := t.lookupUIDWithRetry(protocol, src.Unmap(), srcPort, dst.Unmap(), dstPort)
	if uid < 0 {
		// Unknown UID: Android's getConnectionOwnerUid did not see this
		// connection (typically a SO_BINDTODEVICE leaker like `curl
		// --interface tun0` that skipped per-app VPN tracking).
		//
		// BypassUnknownUID=true: caller explicitly opted into routing such
		// connections to direct (freedom). Tag with bypass inbound.
		//
		// BypassUnknownUID=false with any UID filter active: drop. Without
		// the drop, an unknown packet falls through to the default tunnel
		// handler, which leaks the would-be-bypassed app's traffic into
		// the VPN (precisely the SO_BINDTODEVICE escape this option was
		// meant to close). Excluded-only filter (no bypass/allow lists) is
		// not affected: there "unknown" means "not on the killlist" and
		// should keep tunneling as normal.
		//
		// TunnelUnknownUID=true overrides both: the caller asked to ignore
		// unknown UIDs and let them fall through to the tunnel even with a
		// bypass/allow list active (the app's "unknown UID router off").
		if t.tunnelUnknownUID {
			return uidDecision{}
		}
		if t.bypassUnknownUID && t.bypassInboundTag != "" {
			return uidDecision{tag: t.bypassInboundTag}
		}
		if !t.bypassUnknownUID && (len(t.bypassUIDs) > 0 || len(t.allowedUIDs) > 0) {
			return uidDecision{drop: true}
		}
		return uidDecision{}
	}
	if _, blocked := t.excludedUIDs[uint32(uid)]; blocked {
		return uidDecision{drop: true}
	}
	if len(t.allowedUIDs) > 0 {
		if _, allowed := t.allowedUIDs[uint32(uid)]; !allowed {
			// Not allowlisted. With a bypass inbound configured, divert the
			// connection to direct (xwhitelist: only listed UIDs stay in the
			// tunnel, everyone else egresses directly) instead of dropping it,
			// so non-selected apps keep working. Without a bypass inbound this
			// stays a strict allowlist that drops non-listed UIDs.
			if t.bypassInboundTag != "" {
				return uidDecision{tag: t.bypassInboundTag}
			}
			return uidDecision{drop: true}
		}
	}
	if len(t.bypassUIDs) > 0 {
		if _, bypass := t.bypassUIDs[uint32(uid)]; bypass {
			return uidDecision{tag: t.bypassInboundTag}
		}
	}
	return uidDecision{}
}

const uidLookupRetryInterval = 5 * time.Millisecond

func (t *stackGVisor) lookupUIDWithRetry(protocol int, srcAddr netip.Addr, srcPort uint16, dstAddr netip.Addr, dstPort uint16) int32 {
	uid := lookupConnectionUID(protocol, srcAddr, srcPort, dstAddr, dstPort)
	if uid >= 0 || t.uidLookupTimeout <= 0 {
		return uid
	}
	deadline := time.Now().Add(t.uidLookupTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return uid
		}
		sleepFor := uidLookupRetryInterval
		if sleepFor > remaining {
			sleepFor = remaining
		}
		time.Sleep(sleepFor)
		uid = lookupConnectionUID(protocol, srcAddr, srcPort, dstAddr, dstPort)
		if uid >= 0 {
			return uid
		}
	}
}

// Start is called by Handler to bring stack to life
func (t *stackGVisor) Start() error {
	linkEndpoint, err := t.tun.newEndpoint()
	if err != nil {
		return err
	}

	ipStack, err := createStack(linkEndpoint)
	if err != nil {
		return err
	}

	tcpForwarder := tcp.NewForwarder(ipStack, 0, 65535, func(r *tcp.ForwarderRequest) {
		go func(r *tcp.ForwarderRequest) {
			var wq waiter.Queue
			id := r.ID()

			decision := t.resolveUIDDecision(syscall.IPPROTO_TCP, id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)
			if decision.drop {
				// Drop the SYN by completing the request with rst=true. The app
				// sees a RST and retries via its real interface, which is the
				// expected behavior for an excluded UID.
				r.Complete(true)
				return
			}

			// Perform a TCP three-way handshake.
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				errors.LogError(t.ctx, err.String())
				r.Complete(true)
				return
			}

			options := ep.SocketOptions()
			options.SetKeepAlive(false)
			options.SetReuseAddress(true)
			options.SetReusePort(true)

			t.handler.HandleConnection(
				gonet.NewTCPConn(&wq, ep),
				// local address on the gVisor side is connection destination
				net.TCPDestination(net.IPAddress(id.LocalAddress.AsSlice()), net.Port(id.LocalPort)),
				decision.tag,
			)

			// close the socket
			ep.Close()
			// send connection complete upstream
			r.Complete(false)
		}(r)
	})
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// Use custom UDP packet handler, instead of strict gVisor forwarder, for FullCone NAT support
	udpForwarder := newUdpConnectionHandler(t.handler.HandleConnection, t.writeRawUDPPacket)
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		decision := t.resolveUIDDecision(syscall.IPPROTO_UDP, id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)
		if decision.drop {
			// Mark the packet as consumed so gVisor does not respond with an
			// ICMP unreachable; the excluded app simply gets no answer through
			// the tun and falls back to its real interface.
			return true
		}
		data := pkt.Clone().Data().AsRange().ToSlice()
		// if len(data) == 0 {
		// 	return false
		// }
		// source/destination of the packet we process as incoming, on gVisor side are Remote/Local
		// in other terms, src is the side behind tun, dst is the side behind gVisor
		// this function handle packets passing from the tun to the gVisor, therefore the src/dst assignement
		srcIP := net.IPAddress(id.RemoteAddress.AsSlice())
		dstIP := net.IPAddress(id.LocalAddress.AsSlice())
		if srcIP == nil || dstIP == nil {
			panic(id)
		}
		src := net.UDPDestination(srcIP, net.Port(id.RemotePort))
		dst := net.UDPDestination(dstIP, net.Port(id.LocalPort))
		udpForwarder.HandlePacket(src, dst, data, decision.tag)
		return true
	})
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber4, t.handleICMPv4Packet)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber6, t.handleICMPv6Packet)

	t.stack = ipStack
	t.endpoint = linkEndpoint

	return nil
}

func (t *stackGVisor) writeRawUDPPacket(payload []byte, src net.Destination, dst net.Destination) error {
	udpLen := header.UDPMinimumSize + len(payload)
	srcIP := tcpip.AddrFromSlice(src.Address.IP())
	dstIP := tcpip.AddrFromSlice(dst.Address.IP())

	// build packet with appropriate IP header size
	isIPv4 := dst.Address.Family().IsIPv4()
	ipHdrSize := header.IPv6MinimumSize
	ipProtocol := header.IPv6ProtocolNumber
	if isIPv4 {
		ipHdrSize = header.IPv4MinimumSize
		ipProtocol = header.IPv4ProtocolNumber
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: ipHdrSize + header.UDPMinimumSize,
		Payload:            buffer.MakeWithData(payload),
	})
	defer pkt.DecRef()

	// Build UDP header
	udpHdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udpHdr.Encode(&header.UDPFields{
		SrcPort: uint16(src.Port),
		DstPort: uint16(dst.Port),
		Length:  uint16(udpLen),
	})

	// Calculate and set UDP checksum
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcIP, dstIP, uint16(udpLen))
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(payload, xsum)))

	// Build IP header
	if isIPv4 {
		ipHdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(header.IPv4MinimumSize + udpLen),
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     srcIP,
			DstAddr:     dstIP,
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	} else {
		ipHdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
		ipHdr.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(udpLen),
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           srcIP,
			DstAddr:           dstIP,
		})
	}

	// dispatch the packet
	err := t.stack.WriteRawPacket(defaultNIC, ipProtocol, buffer.MakeWithView(pkt.ToView()))
	if err != nil {
		return errors.New("failed to write raw udp packet back to stack", err)
	}

	return nil
}

// Close is called by Handler to shut down the stack
func (t *stackGVisor) Close() error {
	if t.stack == nil {
		return nil
	}
	t.endpoint.Attach(nil)
	t.stack.Close()
	for _, endpoint := range t.stack.CleanupEndpoints() {
		endpoint.Abort()
	}

	return nil
}

// createStack configure gVisor ip stack
func createStack(ep stack.LinkEndpoint) (*stack.Stack, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		HandleLocal:        false,
	}
	gStack := stack.New(opts)

	err := gStack.CreateNIC(defaultNIC, ep)
	if err != nil {
		return nil, errors.New(err.String())
	}

	gStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: defaultNIC},
		{Destination: header.IPv6EmptySubnet, NIC: defaultNIC},
	})

	err = gStack.SetSpoofing(defaultNIC, true)
	if err != nil {
		return nil, errors.New(err.String())
	}
	err = gStack.SetPromiscuousMode(defaultNIC, true)
	if err != nil {
		return nil, errors.New(err.String())
	}

	cOpt := tcpip.CongestionControlOption("cubic")
	gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &cOpt)
	sOpt := tcpip.TCPSACKEnabled(true)
	gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)

	// Disable RACK/TLP loss recovery to fix connection stalls under high load
	rOpt := tcpip.TCPRecovery(0)
	gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &rOpt)

	tcpRXBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcpRXBufMinSize,
		Default: tcpRXBufDefSize,
		Max:     tcpRXBufMaxSize,
	}
	err = gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRXBufOpt)
	if err != nil {
		return nil, errors.New(err.String())
	}

	tcpTXBufOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcpTXBufMinSize,
		Default: tcpTXBufDefSize,
		Max:     tcpTXBufMaxSize,
	}
	err = gStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTXBufOpt)
	if err != nil {
		return nil, errors.New(err.String())
	}

	return gStack, nil
}
