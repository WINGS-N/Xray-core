package wingswatch

import (
	"sync"
	"sync/atomic"
)

// queueDepth - сколько событий ждёт медленного подписчика. Дальше старое
// выкидывается: наблюдение не должно тормозить проксирование ни на такт
const queueDepth = 4096

// Hub раздаёт события подписчикам. Синглтон, потому что диспетчеру неоткуда
// достать зависимость, не переписав пол-ядра
type Hub struct {
	mu      sync.Mutex
	next    uint64
	streams map[uint64]chan *AccessEvent
	// live - есть ли хоть один подписчик. Читается на каждое соединение, поэтому
	// атомик, а не мьютекс
	live atomic.Bool
	// dropped - сколько событий не влезло. Считаем, иначе тишина неотличима от
	// того, что подписчик молча просрал половину
	dropped atomic.Uint64
}

// Default - тот самый синглтон
var Default = &Hub{streams: map[uint64]chan *AccessEvent{}}

// Active говорит, нужно ли вообще обвешивать соединение счётчиками. Без
// подписчиков наблюдение не стоит ни аллокации
func (h *Hub) Active() bool { return h.live.Load() }

// Dropped - сколько событий выкинуто из-за медленного подписчика
func (h *Hub) Dropped() uint64 { return h.dropped.Load() }

// Subscribe заводит поток событий. Отписка обязательна, иначе канал копит мусор
func (h *Hub) Subscribe() (<-chan *AccessEvent, func()) {
	ch := make(chan *AccessEvent, queueDepth)
	h.mu.Lock()
	id := h.next
	h.next++
	h.streams[id] = ch
	h.live.Store(true)
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if existing, ok := h.streams[id]; ok {
			delete(h.streams, id)
			close(existing)
		}
		h.live.Store(len(h.streams) > 0)
		h.mu.Unlock()
	}
}

// Publish рассылает событие. Никогда не блокирует: подписчик, который не
// успевает, теряет события, а не вешает всю ноду нахуй
func (h *Hub) Publish(event *AccessEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ch := range h.streams {
		select {
		case ch <- event:
		default:
			h.dropped.Add(1)
		}
	}
}
