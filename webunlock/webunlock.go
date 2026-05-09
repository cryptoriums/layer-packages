// Package webunlock provides a minimal HTTP server that waits for a correct
// passphrase before returning. Callers inject a validate function so the same
// package works for any unlock backend (cosmos keyring, GPG pass-store, etc.).
//
// Usage:
//
//	pass, err := webunlock.WaitForUnlock(ctx, ":8888",
//	    func(p string) error { return myKeyring.CheckPass(p) },
//	    logger)
package webunlock

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Logger is the minimal logging interface accepted by this package.
// It is satisfied by cosmossdk.io/log, cosmossdk.io/log/v2,
// github.com/cometbft/cometbft/libs/log, and most other structured loggers.
type Logger interface {
	Info(msg string, keyvals ...any)
	Warn(msg string, keyvals ...any)
	Error(msg string, keyvals ...any)
}

// Config holds optional tuning knobs. Zero values select safe defaults.
type Config struct {
	// MaxFails is the number of wrong-password attempts before rate limiting.
	// Default: 10.
	MaxFails int
	// LockDuration is how long access is blocked after MaxFails consecutive
	// failures. Default: 1 minute.
	LockDuration time.Duration
	// ReadHeaderTimeout for the HTTP server. Default: 5 seconds.
	ReadHeaderTimeout time.Duration
}

// WaitForUnlock starts an HTTP server at addr and blocks until validateFn(pass)
// returns nil. The accepted password is returned so the caller can use it.
// Cancel ctx to abort before a password is accepted.
//
// The server is shut down automatically after success or cancellation.
func WaitForUnlock(ctx context.Context, addr string, validateFn func(pass string) error, logger Logger) (string, error) {
	return WaitForUnlockWithConfig(ctx, addr, validateFn, Config{}, logger)
}

// WaitForUnlockWithConfig is like WaitForUnlock but accepts custom Config.
func WaitForUnlockWithConfig(ctx context.Context, addr string, validateFn func(pass string) error, cfg Config, logger Logger) (string, error) {
	if cfg.MaxFails <= 0 {
		cfg.MaxFails = 10
	}
	if cfg.LockDuration <= 0 {
		cfg.LockDuration = time.Minute
	}
	if cfg.ReadHeaderTimeout <= 0 {
		cfg.ReadHeaderTimeout = 5 * time.Second
	}

	rl := &rateLimiter{maxFails: cfg.MaxFails, lockDuration: cfg.LockDuration}
	page := template.Must(template.New("unlock").Parse(pageTmpl))
	passCh := make(chan string, 1)

	var (
		shutdownOnce sync.Once
		srv          *http.Server
	)
	doShutdown := func() {
		shutdownOnce.Do(func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if srv != nil {
				if err := srv.Shutdown(shutCtx); err != nil {
					logger.Error("webunlock: shutdown error", "err", err)
				}
			}
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("webunlock: panic recovered", "remote", r.RemoteAddr, "panic", fmt.Sprintf("%v", rec))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()

		if wait, locked := rl.check(); locked {
			logger.Warn("webunlock: rate limited", "remote", r.RemoteAddr, "wait", wait.Truncate(time.Second).String())
			renderPage(w, page, pageData{Locked: true, Wait: wait.Truncate(time.Second)})
			return
		}

		var errMsg string

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			pass := strings.TrimSpace(r.FormValue("pass"))
			switch {
			case pass == "":
				rl.fail()
				errMsg = "Password is required"
				logger.Warn("webunlock: empty password attempt", "remote", r.RemoteAddr)
			case validateFn(pass) == nil:
				rl.reset()
				logger.Info("webunlock: unlocked", "remote", r.RemoteAddr)
				_, _ = io.WriteString(w, "unlocked")
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				select {
				case passCh <- pass:
				default:
				}
				go doShutdown()
				return
			default:
				rl.fail()
				errMsg = "Incorrect password"
				logger.Warn("webunlock: wrong password", "remote", r.RemoteAddr)
			}
		}

		renderPage(w, page, pageData{Err: errMsg})
	})

	ln, err := net.Listen("tcp", addr) //nolint:gosec // G102: intentionally binds to all interfaces
	if err != nil {
		return "", fmt.Errorf("webunlock: listen %s: %w", addr, err)
	}

	srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
	}

	logger.Info("webunlock: listening", "addr", "http://"+addr)

	srvErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	select {
	case <-ctx.Done():
		doShutdown()
		return "", ctx.Err()
	case pass := <-passCh:
		return pass, nil
	case err := <-srvErr:
		return "", fmt.Errorf("webunlock: server error: %w", err)
	}
}

// ── HTML page ────────────────────────────────────────────────────────────────

type pageData struct {
	Locked bool
	Wait   time.Duration
	Err    string
}

const pageTmpl = `<!doctype html>
<html><head><meta charset="utf-8"><title>Unlock</title>
<style>
body{font-family:sans-serif;margin:2rem}
label{min-width:10em;display:inline-block;margin:.35rem 0}
.notice{color:#c00}.ok{color:#060}
</style></head><body>
{{if .Locked}}<p class="notice">Too many failures. Try again in {{.Wait}}.</p>{{end}}
{{if .Err}}<p class="notice">{{.Err}}</p>{{end}}
<form method="post">
  <label for="pass">Password:</label>
  <input id="pass" name="pass" type="password" autofocus required>
  <button type="submit">Unlock</button>
</form>
</body></html>`

func renderPage(w http.ResponseWriter, tmpl *template.Template, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, data)
}

// ── Rate limiter ─────────────────────────────────────────────────────────────

type rateLimiter struct {
	mu           sync.Mutex
	fails        int
	lockUntil    time.Time
	maxFails     int
	lockDuration time.Duration
}

func (r *rateLimiter) check() (time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Now().Before(r.lockUntil) {
		return time.Until(r.lockUntil), true
	}
	return 0, false
}

func (r *rateLimiter) fail() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fails++
	if r.fails >= r.maxFails {
		r.lockUntil = time.Now().Add(r.lockDuration)
		r.fails = 0
	}
}

func (r *rateLimiter) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fails = 0
	r.lockUntil = time.Time{}
}
