package tlsprint

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// realClientHello поднимает настоящий TLS-клиент и ловит его первый пакет.
// Хендшейк собранный руками доказывает только то, что разбор понимает сам себя
func realClientHello(t *testing.T, conf *tls.Config) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		got <- buf[:n]
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Хендшейк не сойдётся, слушатель просто читает байты, и это ровно то, что нужно
	_ = tls.Client(conn, conf).HandshakeContext(ctx)

	select {
	case b := <-got:
		if len(b) == 0 {
			t.Fatal("клиент не прислал ни байта")
		}
		return b
	case <-time.After(3 * time.Second):
		t.Fatal("ClientHello не приехал")
		return nil
	}
}

func TestParseRealClientHello(t *testing.T) {
	hello := realClientHello(t, &tls.Config{
		ServerName: "example.org",
		NextProtos: []string{"h2", "http/1.1"},
	})
	print, ok := Parse(hello)
	if !ok {
		t.Fatal("настоящий ClientHello не разобрался")
	}
	if len(print.JA3Hash) != 32 {
		t.Fatalf("хэш JA3 = %q, а это должен быть MD5", print.JA3Hash)
	}
	if !strings.HasPrefix(print.JA4, "t13d") {
		t.Fatalf("JA4 = %q, а клиент шёл по TCP с SNI и TLS 1.3", print.JA4)
	}
	parts := strings.Split(print.JA4, "_")
	if len(parts) != 3 || len(parts[1]) != 12 || len(parts[2]) != 12 {
		t.Fatalf("JA4 = %q, а формат это три куска с хвостами по 12 знаков", print.JA4)
	}
	if !strings.Contains(print.JA4, "h2") {
		t.Fatalf("JA4 = %q, а первым ALPN клиент предложил h2", print.JA4)
	}
}

// Один и тот же стек обязан давать один отпечаток, иначе он ничего не ловит, а
// разные настройки клиента - разный
func TestFingerprintIsStableAndDistinguishes(t *testing.T) {
	conf := &tls.Config{ServerName: "example.org", NextProtos: []string{"h2"}}
	first, ok := Parse(realClientHello(t, conf))
	if !ok {
		t.Fatal("первый хендшейк не разобрался")
	}
	second, ok := Parse(realClientHello(t, conf))
	if !ok {
		t.Fatal("второй хендшейк не разобрался")
	}
	if first.JA4 != second.JA4 || first.JA3Hash != second.JA3Hash {
		t.Fatalf("один клиент дал два отпечатка: %q и %q", first.JA4, second.JA4)
	}

	other, ok := Parse(realClientHello(t, &tls.Config{
		ServerName:   "example.org",
		NextProtos:   []string{"h2"},
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		MaxVersion:   tls.VersionTLS12,
	}))
	if !ok {
		t.Fatal("урезанный клиент не разобрался")
	}
	if other.JA4 == first.JA4 {
		t.Fatalf("два разных стека дали один JA4 %q", other.JA4)
	}
	if !strings.HasPrefix(other.JA4, "t12d") {
		t.Fatalf("JA4 = %q, а клиента прибили к TLS 1.2", other.JA4)
	}
}

func TestParseRejectsWhatIsNotAHandshake(t *testing.T) {
	for name, b := range map[string][]byte{
		"пусто":       nil,
		"http":        []byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"),
		"обрезанный":  {0x16, 0x03, 0x01, 0x02, 0x00, 0x01},
		"не хендшейк": {0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5},
	} {
		if _, ok := Parse(b); ok {
			t.Fatalf("%s разобралось как ClientHello", name)
		}
	}
}

func TestSlotKeepsFirstSuccess(t *testing.T) {
	ctx := WithSlot(context.Background())
	if _, ok := FromContext(ctx); ok {
		t.Fatal("пустой слот отдал отпечаток")
	}
	Record(ctx, []byte("не тлс"))
	if _, ok := FromContext(ctx); ok {
		t.Fatal("мусор записался как отпечаток")
	}
	hello := realClientHello(t, &tls.Config{ServerName: "example.org"})
	Record(ctx, hello)
	first, ok := FromContext(ctx)
	if !ok {
		t.Fatal("слот не принял разобранный хендшейк")
	}
	Record(ctx, realClientHello(t, &tls.Config{ServerName: "example.org", MaxVersion: tls.VersionTLS12}))
	second, _ := FromContext(ctx)
	if second.JA4 != first.JA4 {
		t.Fatal("слот перезаписал отпечаток вторым хендшейком")
	}
}

// Без слота учёт молчит, и это режим по умолчанию для всего, что мимо нас
func TestRecordWithoutSlotDoesNothing(t *testing.T) {
	ctx := context.Background()
	Record(ctx, realClientHello(t, &tls.Config{ServerName: "example.org"}))
	if _, ok := FromContext(ctx); ok {
		t.Fatal("отпечаток взялся там, где слота нет")
	}
}
