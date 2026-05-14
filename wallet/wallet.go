// Package wallet provides keyring unlock helpers shared between the layer chain
// node and layer-daemons. It wraps webunlock for the HTTP-based unlock flow and
// exposes keyring creation and passphrase validation backed by Cosmos SDK.
package wallet

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/cryptoriums/layer-packages/webunlock"
	"github.com/spf13/viper"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

var (
	mu        sync.Mutex
	passCache string
	passReady chan struct{}
	initOnce  sync.Once
)

// NewKeyring creates a new keyring using the keyring-backend and keyring-dir
// (falling back to home) viper settings, unlocked with pass.
func NewKeyring(pass string, c codec.Codec) (keyring.Keyring, error) {
	krBackend := viper.GetString("keyring-backend")
	if krBackend == "" {
		return nil, fmt.Errorf("keyring-backend not set")
	}
	krDir := viper.GetString("keyring-dir")
	if krDir == "" {
		krDir = viper.GetString("home")
	}
	if krDir == "" {
		return nil, fmt.Errorf("keyring directory not set")
	}
	return keyring.New(sdk.KeyringServiceName(), krBackend, krDir, strings.NewReader(pass), c)
}

// ValidatePass validates pass by opening the keyring and signing a test message
// with the key named by the "key-name" (or "from") viper setting.
func ValidatePass(pass string, c codec.Codec) error {
	if c == nil {
		return fmt.Errorf("codec not provided")
	}
	kr, err := NewKeyring(pass, c)
	if err != nil {
		return err
	}
	keyName := viper.GetString("key-name")
	if keyName == "" {
		keyName = viper.GetString("from")
	}
	if keyName == "" {
		return fmt.Errorf("key-name not set")
	}
	_, _, err = kr.Sign(keyName, []byte("wallet unlock validation"), 1)
	return err
}

// Reader returns a passphrase reader. In web mode it blocks until Init delivers
// a validated passphrase and then returns a reader wrapping it. In non-web mode
// it returns os.Stdin immediately.
func Reader() (io.Reader, error) {
	if !strings.EqualFold(os.Getenv("KEYRING_UNLOCK_MODE"), "web") {
		return os.Stdin, nil
	}
	mu.Lock()
	ready := passReady
	mu.Unlock()
	if ready != nil {
		<-ready
	}
	mu.Lock()
	pass := passCache
	mu.Unlock()
	return strings.NewReader(pass + "\n"), nil
}

// GetKeyring returns a keyring ready for use. In web mode it blocks until the
// wallet has been unlocked via Init. In non-web mode it reads the passphrase
// from stdin.
func GetKeyring(c codec.Codec) (keyring.Keyring, error) {
	reader, err := Reader()
	if err != nil {
		return nil, err
	}
	krBackend := viper.GetString("keyring-backend")
	if krBackend == "" {
		return nil, fmt.Errorf("keyring-backend not set")
	}
	krDir := viper.GetString("keyring-dir")
	if krDir == "" {
		krDir = viper.GetString("home")
	}
	if krDir == "" {
		return nil, fmt.Errorf("keyring directory not set")
	}
	return keyring.New(sdk.KeyringServiceName(), krBackend, krDir, reader, c)
}

// WaitUnlocked returns a channel that is closed once the wallet is unlocked.
// Returns nil when not in web mode (immediately available).
func WaitUnlocked() <-chan struct{} {
	if !strings.EqualFold(os.Getenv("KEYRING_UNLOCK_MODE"), "web") {
		return nil
	}
	mu.Lock()
	ready := passReady
	mu.Unlock()
	return ready
}

// Init starts the web unlock server once (KEYRING_UNLOCK_MODE=web) and caches
// the passphrase so that Reader/GetKeyring can return it on demand. In non-web
// mode Init is a no-op. logger must satisfy the webunlock.Logger interface
// (Info/Warn/Error methods with variadic keyvals).
func Init(logger webunlock.Logger, c codec.Codec, port int) {
	if !strings.EqualFold(os.Getenv("KEYRING_UNLOCK_MODE"), "web") {
		return
	}
	initOnce.Do(func() {
		mu.Lock()
		if passCache != "" {
			mu.Unlock()
			return
		}
		ready := make(chan struct{})
		passReady = ready
		mu.Unlock()

		// Redirect stdin to /dev/null so the keyring does not block on a
		// terminal prompt while we wait for the HTTP unlock.
		if f, err := os.Open("/dev/null"); err == nil {
			_ = syscall.Dup2(int(f.Fd()), int(os.Stdin.Fd()))
			_ = f.Close()
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		go func() { <-ctx.Done(); stop() }()

		addr := fmt.Sprintf(":%d", port)
		go func() {
			pass, err := webunlock.WaitForUnlock(ctx, addr, func(p string) error {
				return ValidatePass(p, c)
			}, logger)
			if err != nil {
				logger.Error("wallet webunlock failed", "error", err)
				return
			}
			mu.Lock()
			passCache = pass
			mu.Unlock()
			close(ready)
			logger.Info("wallet unlocked successfully")
		}()
	})
}
