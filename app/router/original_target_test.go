package router

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing/dns"
	routingsession "github.com/xtls/xray-core/features/routing/session"
)

// The address a connection was opened to is still there once a sniffer has put
// a domain in its place, through the wrapper that resolves as well.
func TestOriginalTargetSurvivesTheSniffer(t *testing.T) {
	opened := net.TCPDestination(net.ParseAddress("93.184.216.34"), 443)
	ctx := &routingsession.Context{
		Outbound: &session.Outbound{
			Target:         net.TCPDestination(net.DomainAddress("example.com"), 443),
			OriginalTarget: opened,
		},
	}
	if got := originalTarget(ctx); got != opened {
		t.Fatalf("the address of the connection is %s, want %s", got, opened)
	}
	if got := originalTarget(&dns.ResolvableContext{Context: ctx}); got != opened {
		t.Fatalf("through the resolvable wrapper it is %s, want %s", got, opened)
	}
}

// A context that carries no outbound has no address to give.
func TestOriginalTargetOfNothing(t *testing.T) {
	if got := originalTarget(&routingsession.Context{}); got.IsValid() {
		t.Fatalf("a context without an outbound gave %s", got)
	}
}
