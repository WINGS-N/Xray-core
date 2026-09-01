package dispatcher

import (
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/xtls/xray-core/common/buf"
)

type countingWriter struct {
	written int32
}

func (w *countingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.written += mb.Len()
	buf.ReleaseMulti(mb)
	return nil
}

func payload(size int) buf.MultiBuffer {
	b := buf.New()
	b.Extend(int32(size))
	return buf.MultiBuffer{b}
}

// A capped user is paced: the second second's worth of traffic cannot go out
// in the same instant as the first
func TestRateLimitWriterPaces(t *testing.T) {
	const bps = 4096
	sink := &countingWriter{}
	writer := newRateLimitWriter(sink, rate.NewLimiter(rate.Limit(bps), bps))

	start := time.Now()
	// Первый буфер уходит из накопленного бакета, второй уже ждёт
	for i := 0; i < 2; i++ {
		if err := writer.WriteMultiBuffer(payload(bps)); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)

	if sink.written != 2*bps {
		t.Fatalf("прошло %d байт, want %d", sink.written, 2*bps)
	}
	if elapsed < 700*time.Millisecond {
		t.Fatalf("лимит не притормозил: %s на два бакета по %d B/s", elapsed, bps)
	}
}

// Буфер больше бакета не должен обрывать соединение: он оплачивается частями
func TestRateLimitWriterHandlesOversizedBuffer(t *testing.T) {
	const bps = 1024
	sink := &countingWriter{}
	writer := newRateLimitWriter(sink, rate.NewLimiter(rate.Limit(bps*100), bps))

	if err := writer.WriteMultiBuffer(payload(bps * 4)); err != nil {
		t.Fatalf("буфер больше бакета не прошёл: %v", err)
	}
	if sink.written != bps*4 {
		t.Fatalf("прошло %d байт, want %d", sink.written, bps*4)
	}
}

// Без лимита обёртка не навешивается вовсе
func TestNoLimiterMeansNoWrapper(t *testing.T) {
	sink := &countingWriter{}
	if got := newRateLimitWriter(sink, nil); got != buf.Writer(sink) {
		t.Fatal("писателя обернули без лимита")
	}
}

// Лимитеры выдаются на пользователя, а не на соединение
func TestLimitersAreSharedPerUser(t *testing.T) {
	limits := newUserLimiters()
	first := limits.Uplink("user@example.com", 1000)
	second := limits.Uplink("user@example.com", 1000)
	if first != second {
		t.Fatal("на каждое соединение выдан свой лимитер - это не лимит")
	}
	if other := limits.Uplink("someone@example.com", 1000); other == first {
		t.Fatal("разные пользователи делят один лимитер")
	}
	if none := limits.Uplink("user@example.com", 0); none != nil {
		t.Fatal("нулевая скорость должна означать отсутствие лимита")
	}
	limits.Forget("user@example.com")
	if again := limits.Uplink("user@example.com", 1000); again == first {
		t.Fatal("Forget не выбросил лимитер")
	}
}
