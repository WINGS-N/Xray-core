package watch

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/app/wingsvpn/tlsprint"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

// countingReader считает, сколько клиент отдал наверх
type countingReader struct {
	inner buf.Reader
	n     *atomic.Uint64
}

func (r *countingReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.inner.ReadMultiBuffer()
	if n := mb.Len(); n > 0 {
		r.n.Add(uint64(n))
	}
	return mb, err
}

func (r *countingReader) Close() error { return common.Close(r.inner) }

func (r *countingReader) Interrupt() { common.Interrupt(r.inner) }

// countingWriter считает, сколько прилетело клиенту вниз
type countingWriter struct {
	inner buf.Writer
	n     *atomic.Uint64
}

func (w *countingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if n := mb.Len(); n > 0 {
		w.n.Add(uint64(n))
	}
	return w.inner.WriteMultiBuffer(mb)
}

func (w *countingWriter) Close() error { return common.Close(w.inner) }

func (w *countingWriter) Interrupt() { common.Interrupt(w.inner) }

// Observe обвешивает соединение счётчиками и возвращает то, что надо позвать
// после того, как проксирование закончилось. Без подписчиков не делает нихуя
func Observe(ctx context.Context, dest net.Destination, link *transport.Link, outboundTag string) (*transport.Link, func()) {
	if !Default.Active() {
		return link, func() {}
	}
	var up, down atomic.Uint64
	started := time.Now()
	wrapped := &transport.Link{
		Reader: &countingReader{inner: link.Reader, n: &up},
		Writer: &countingWriter{inner: link.Writer, n: &down},
	}
	return wrapped, func() {
		event := &AccessEvent{
			AtUnixNano:  started.UnixNano(),
			OutboundTag: outboundTag,
			TargetPort:  uint32(dest.Port),
			Network:     dest.Network.SystemString(),
			UpBytes:     up.Load(),
			DownBytes:   down.Load(),
			DurationMs:  uint32(time.Since(started).Milliseconds()),
		}
		// Домен есть только со включённым sniffing, иначе тут голый адрес и
		// смотреть в нём нечего
		if dest.Address != nil {
			if dest.Address.Family().IsDomain() {
				event.TargetDomain = dest.Address.Domain()
			} else {
				event.TargetIp = dest.Address.IP().String()
			}
		}
		if print, ok := tlsprint.FromContext(ctx); ok {
			event.TlsJa3 = print.JA3Hash
			event.TlsJa4 = print.JA4
		}
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			event.InboundTag = inbound.Tag
			if inbound.Source.Address != nil {
				event.SourceIp = inbound.Source.Address.String()
			}
			if inbound.User != nil {
				event.Email = inbound.User.Email
			}
		}
		Default.Publish(event)
	}
}
