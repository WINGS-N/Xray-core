//go:build linux

package tun

import (
	"bufio"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// procFiles lists every /proc/net table that may contain the owner of a TUN
// connection. Order matters only for cache hit rate: TCP is overwhelmingly
// the common case for new connections, so we probe it first.
var procFiles = []string{
	"/proc/net/tcp",
	"/proc/net/tcp6",
	"/proc/net/udp",
	"/proc/net/udp6",
}

// uidCacheEntry pins the resolved UID together with the time we observed it.
// We rely on TTL only as a way to drop stale entries on a long-running peer;
// since the table is keyed by the full 4-tuple, recycled ports map to a new
// entry rather than a stale hit.
type uidCacheEntry struct {
	uid       int32
	expiresAt time.Time
}

var (
	uidCacheMu  sync.Mutex
	uidCache    = make(map[string]uidCacheEntry)
	uidCacheTTL = 30 * time.Second
)

// lookupConnectionUID returns the UID owning the kernel socket whose local
// 5-tuple matches (srcAddr, srcPort, dstAddr, dstPort). Returns -1 when the
// /proc tables do not list the connection (yet) or when the file is not
// readable. The TUN handler treats -1 as "unknown" and never blocks on it,
// so a transient miss never causes a packet to be dropped silently.
func lookupConnectionUID(srcAddr netip.Addr, srcPort uint16, dstAddr netip.Addr, dstPort uint16) int32 {
	key := buildCacheKey(srcAddr, srcPort, dstAddr, dstPort)
	if uid, ok := readCache(key); ok {
		return uid
	}

	srcHex := encodeAddrPort(srcAddr, srcPort)
	dstHex := encodeAddrPort(dstAddr, dstPort)
	uid := scanProcTables(srcAddr, srcHex, dstHex)
	if uid >= 0 {
		writeCache(key, uid)
	}
	return uid
}

func buildCacheKey(srcAddr netip.Addr, srcPort uint16, dstAddr netip.Addr, dstPort uint16) string {
	var b strings.Builder
	b.WriteString(srcAddr.String())
	b.WriteByte(':')
	b.WriteString(strconv.FormatUint(uint64(srcPort), 10))
	b.WriteByte('>')
	b.WriteString(dstAddr.String())
	b.WriteByte(':')
	b.WriteString(strconv.FormatUint(uint64(dstPort), 10))
	return b.String()
}

func readCache(key string) (int32, bool) {
	uidCacheMu.Lock()
	defer uidCacheMu.Unlock()
	entry, ok := uidCache[key]
	if !ok {
		return -1, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(uidCache, key)
		return -1, false
	}
	return entry.uid, true
}

func writeCache(key string, uid int32) {
	uidCacheMu.Lock()
	defer uidCacheMu.Unlock()
	uidCache[key] = uidCacheEntry{uid: uid, expiresAt: time.Now().Add(uidCacheTTL)}
}

// scanProcTables walks the relevant /proc/net/* files, returning the first
// UID whose local/remote hex matches the connection.
//
// IPv4 sockets normally live in /proc/net/{tcp,udp} but apps that opened a
// dual-stack socket (AF_INET6 bound to ::ffff:0) show up under /proc/net/
// {tcp6,udp6} with the IPv4 address in the lower 32 bits and ::ffff:0/96 in
// the upper bits. We probe both representations for IPv4 traffic.
func scanProcTables(srcAddr netip.Addr, srcHex, dstHex string) int32 {
	if !srcAddr.Is4() {
		return scanFiles([]string{"/proc/net/tcp6", "/proc/net/udp6"}, srcHex, dstHex)
	}
	if uid := scanFiles([]string{"/proc/net/tcp", "/proc/net/udp"}, srcHex, dstHex); uid >= 0 {
		return uid
	}
	srcPort, srcWithoutPort := splitHexPort(srcHex)
	dstPort, dstWithoutPort := splitHexPort(dstHex)
	if srcWithoutPort == "" || dstWithoutPort == "" {
		return -1
	}
	mapPrefix := "00000000000000000000FFFF"
	mappedSrcHex := mapPrefix + srcWithoutPort + ":" + srcPort
	mappedDstHex := mapPrefix + dstWithoutPort + ":" + dstPort
	return scanFiles([]string{"/proc/net/tcp6", "/proc/net/udp6"}, mappedSrcHex, mappedDstHex)
}

func splitHexPort(combined string) (port, addr string) {
	idx := strings.LastIndex(combined, ":")
	if idx < 0 {
		return "", ""
	}
	return combined[idx+1:], combined[:idx]
}

func scanFiles(files []string, srcHex, dstHex string) int32 {
	for _, path := range files {
		if uid := scanFile(path, srcHex, dstHex); uid >= 0 {
			return uid
		}
	}
	return -1
}

func scanFile(path, srcHex, dstHex string) int32 {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	// /proc/net/tcp lines can be longer than the default 64KiB buffer when the
	// system has tens of thousands of sockets. Pre-size to a comfortable cap.
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if !strings.EqualFold(fields[1], srcHex) {
			continue
		}
		if !strings.EqualFold(fields[2], dstHex) {
			continue
		}
		uid64, err := strconv.ParseInt(fields[7], 10, 32)
		if err != nil {
			continue
		}
		return int32(uid64)
	}
	return -1
}

// encodeAddrPort turns a (netip.Addr, port) pair into the /proc/net wire
// encoding: lowercased hex of the address bytes (little-endian per 32-bit
// word for IPv4, big-endian per 32-bit word for IPv6 written as 8x 16-bit
// groups), followed by ":PORT" with port in uppercase hex.
func encodeAddrPort(addr netip.Addr, port uint16) string {
	var b strings.Builder
	if addr.Is4() {
		ip := addr.As4()
		// /proc/net/tcp prints IPv4 addresses as 32-bit little-endian hex,
		// i.e. byte 3 first, then 2, 1, 0.
		hexDigits := "0123456789ABCDEF"
		buf := make([]byte, 8)
		for i := 0; i < 4; i++ {
			byteVal := ip[3-i]
			buf[i*2] = hexDigits[byteVal>>4]
			buf[i*2+1] = hexDigits[byteVal&0xF]
		}
		b.Write(buf)
	} else {
		ip := addr.As16()
		hexDigits := "0123456789ABCDEF"
		buf := make([]byte, 32)
		// /proc/net/tcp6 prints IPv6 in 32-bit words, each word reversed.
		for word := 0; word < 4; word++ {
			for i := 0; i < 4; i++ {
				byteVal := ip[word*4+3-i]
				buf[word*8+i*2] = hexDigits[byteVal>>4]
				buf[word*8+i*2+1] = hexDigits[byteVal&0xF]
			}
		}
		b.Write(buf)
	}
	b.WriteByte(':')
	portBuf := []byte{0, 0, 0, 0}
	hexDigits := "0123456789ABCDEF"
	portBuf[0] = hexDigits[(port>>12)&0xF]
	portBuf[1] = hexDigits[(port>>8)&0xF]
	portBuf[2] = hexDigits[(port>>4)&0xF]
	portBuf[3] = hexDigits[port&0xF]
	b.Write(portBuf)
	return b.String()
}
