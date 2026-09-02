package watch

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

func TestObserveIsFreeWithoutSubscribers(t *testing.T) {
	link := &transport.Link{}
	got, finish := Observe(context.Background(), net.TCPDestination(net.DomainAddress("example.com"), 443), link, "out")
	if got != link {
		t.Fatal("соединение обвесили счётчиками, хотя никто не подписан")
	}
	finish()
}

func TestObserveReportsBytesAndIdentity(t *testing.T) {
	events, unsubscribe := Default.Subscribe()
	defer unsubscribe()

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    "fed-tcp",
		Source: net.TCPDestination(net.ParseAddress("203.0.113.7"), 51234),
		User:   &protocol.MemoryUser{Email: "f-abc12345"},
	})
	dest := net.TCPDestination(net.DomainAddress("example.com"), 443)

	reader := buf.NewReader(buf.New())
	writer := buf.Discard
	wrapped, finish := Observe(ctx, dest, &transport.Link{Reader: reader, Writer: writer}, "proxy")

	payload := buf.New()
	payload.Write([]byte("0123456789"))
	if err := wrapped.Writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
		t.Fatalf("запись разъебалась: %v", err)
	}
	finish()

	select {
	case event := <-events:
		if event.GetEmail() != "f-abc12345" {
			t.Fatalf("профиль потерян: %q", event.GetEmail())
		}
		if event.GetTargetDomain() != "example.com" {
			t.Fatalf("домен потерян: %q", event.GetTargetDomain())
		}
		if event.GetSourceIp() != "203.0.113.7" {
			t.Fatalf("адрес клиента потерян: %q", event.GetSourceIp())
		}
		if event.GetDownBytes() != 10 {
			t.Fatalf("вниз насчитали %d вместо 10", event.GetDownBytes())
		}
		if event.GetInboundTag() != "fed-tcp" || event.GetOutboundTag() != "proxy" {
			t.Fatalf("теги потеряны: %q %q", event.GetInboundTag(), event.GetOutboundTag())
		}
	default:
		t.Fatal("событие не приехало вообще")
	}
}

func TestPublishDropsInsteadOfBlocking(t *testing.T) {
	events, unsubscribe := Default.Subscribe()
	defer unsubscribe()

	before := Default.Dropped()
	for i := 0; i < queueDepth+16; i++ {
		Default.Publish(&AccessEvent{Email: "f-flood"})
	}
	if Default.Dropped() <= before {
		t.Fatal("переполнение не посчитали, тишина неотличима от потери")
	}
	if len(events) != queueDepth {
		t.Fatalf("в очереди %d, а должно быть ровно %d", len(events), queueDepth)
	}
}
