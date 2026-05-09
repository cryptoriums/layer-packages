package webunlock_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cryptoriums/layer-packages/webunlock"
)

// nopLogger discards all log output.
type nopLogger struct{}

func (nopLogger) Info(_ string, _ ...any)  {}
func (nopLogger) Warn(_ string, _ ...any)  {}
func (nopLogger) Error(_ string, _ ...any) {}

// freeAddr returns a free "127.0.0.1:port" address.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeAddr: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// startUnlock launches WaitForUnlock in a goroutine and returns the address
// plus a channel that delivers the result when the server exits.
func startUnlock(t *testing.T, ctx context.Context, validateFn func(string) error) (addr string, done <-chan error) {
	t.Helper()
	addr = freeAddr(t)
	ch := make(chan error, 1)
	go func() {
		_, err := webunlock.WaitForUnlock(ctx, addr, validateFn, nopLogger{})
		ch <- err
	}()
	// Give server time to bind.
	time.Sleep(60 * time.Millisecond)
	return addr, ch
}

func startUnlockWithCfg(t *testing.T, ctx context.Context, validateFn func(string) error, cfg webunlock.Config) (addr string, done <-chan string) {
	t.Helper()
	addr = freeAddr(t)
	ch := make(chan string, 1)
	go func() {
		p, _ := webunlock.WaitForUnlockWithConfig(ctx, addr, validateFn, cfg, nopLogger{})
		ch <- p
	}()
	time.Sleep(60 * time.Millisecond)
	return addr, ch
}

func postForm(t *testing.T, url, pass string) string {
	t.Helper()
	resp, err := http.PostForm(url, map[string][]string{"pass": {pass}})
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestWaitForUnlock_CorrectPassword(t *testing.T) {
	const want = "correct-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addr := freeAddr(t)
	resultCh := make(chan struct {
		pass string
		err  error
	}, 1)
	go func() {
		p, e := webunlock.WaitForUnlock(ctx, addr, func(p string) error {
			if p == want {
				return nil
			}
			return errors.New("wrong")
		}, nopLogger{})
		resultCh <- struct {
			pass string
			err  error
		}{p, e}
	}()
	time.Sleep(60 * time.Millisecond)

	body := postForm(t, "http://"+addr+"/", want)
	if !strings.Contains(body, "unlocked") {
		t.Errorf("expected 'unlocked' in body, got: %q", body)
	}

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}
	if result.pass != want {
		t.Errorf("returned pass=%q, want %q", result.pass, want)
	}
}

func TestWaitForUnlock_WrongThenCorrectPassword(t *testing.T) {
	const want = "s3cr3t"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addr, done := startUnlock(t, ctx, func(p string) error {
		if p == want {
			return nil
		}
		return errors.New("wrong")
	})

	// Wrong password — must NOT unlock.
	body := postForm(t, "http://"+addr+"/", "badpass")
	if strings.Contains(body, "unlocked") {
		t.Fatal("wrong password unlocked the server")
	}

	// Correct password — must unlock.
	body = postForm(t, "http://"+addr+"/", want)
	if !strings.Contains(body, "unlocked") {
		t.Errorf("correct password did not unlock: %q", body)
	}

	if err := <-done; err != nil {
		t.Fatalf("WaitForUnlock error: %v", err)
	}
}

func TestWaitForUnlock_EmptyPasswordRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addr, _ := startUnlock(t, ctx, func(string) error { return nil })

	body := postForm(t, "http://"+addr+"/", "")
	if strings.Contains(body, "unlocked") {
		t.Error("empty password should be rejected")
	}
}

func TestWaitForUnlock_GETReturnsForm(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addr, _ := startUnlock(t, ctx, func(string) error { return errors.New("x") })

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<form") {
		t.Errorf("GET should return HTML form, got: %q", body)
	}
}

func TestWaitForUnlock_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	addr, done := startUnlock(t, ctx, func(string) error { return errors.New("x") })
	_ = addr

	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("did not return after context cancellation")
	}
}

func TestWaitForUnlock_RateLimiting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := webunlock.Config{
		MaxFails:     3,
		LockDuration: 500 * time.Millisecond,
	}
	addr, _ := startUnlockWithCfg(t, ctx, func(string) error { return errors.New("x") }, cfg)

	// Exhaust allowed failures.
	for i := 0; i < 3; i++ {
		postForm(t, "http://"+addr+"/", "bad")
	}

	// Next attempt should be rate-limited.
	body := postForm(t, "http://"+addr+"/", "bad")
	if !strings.Contains(body, "Too many failures") {
		t.Errorf("expected rate-limit message, got: %q", body)
	}
}

func TestWaitForUnlock_ServerShutsDownAfterUnlock(t *testing.T) {
	const pass = "open-sesame"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addr, done := startUnlock(t, ctx, func(p string) error {
		if p == pass {
			return nil
		}
		return errors.New("x")
	})

	postForm(t, "http://"+addr+"/", pass)

	// Server should shut down — WaitForUnlock must return without error.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil error after unlock, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("server did not shut down after successful unlock")
	}

	// Subsequent request must fail (server is gone).
	time.Sleep(100 * time.Millisecond)
	_, err := http.Get("http://" + addr + "/")
	if err == nil {
		t.Error("expected connection refused after shutdown, but request succeeded")
	}
}
