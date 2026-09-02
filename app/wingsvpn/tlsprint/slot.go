package tlsprint

import (
	"context"
	"sync"
)

type slotKey struct{}

// Slot держит отпечаток от сниффера до конца проксирования. Сниффер и учёт
// разнесены по разным горутинам, поэтому под замком
type Slot struct {
	mu    sync.Mutex
	print Print
	ok    bool
}

// WithSlot вешает на соединение место под отпечаток. Без него Record не делает
// нихуя, и это нормальный режим для всего, что не наше
func WithSlot(ctx context.Context) context.Context {
	if ctx.Value(slotKey{}) != nil {
		return ctx
	}
	return context.WithValue(ctx, slotKey{}, &Slot{})
}

// Record считает отпечаток по сниффленным байтам. Зовётся на каждой попытке
// сниффинга, а хендшейк приезжает не всегда целиком, поэтому первый удачный
// разбор и остаётся
func Record(ctx context.Context, payload []byte) {
	slot, _ := ctx.Value(slotKey{}).(*Slot)
	if slot == nil {
		return
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.ok {
		return
	}
	if print, ok := Parse(payload); ok {
		slot.print, slot.ok = print, true
	}
}

// FromContext отдаёт то, что удалось снять
func FromContext(ctx context.Context) (Print, bool) {
	slot, _ := ctx.Value(slotKey{}).(*Slot)
	if slot == nil {
		return Print{}, false
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	return slot.print, slot.ok
}
