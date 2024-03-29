package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/italypaleale/unlocker/pkg/utils"
	"github.com/rs/zerolog"
)

const (
	tlsCertFile   = "tls-cert.pem"
	tlsKeyFile    = "tls-key.pem"
	minTLSVersion = tls.VersionTLS12
)

type tlsCertWatchFn = func(ctx context.Context, logger *zerolog.Logger) error

type tlsCertProvider struct {
	lock    sync.RWMutex
	tlsCert *tls.Certificate
	path    string
	cert    string
	key     string
}

func newTLSCertProvider(path string) (*tlsCertProvider, error) {
	var exists bool

	// Check if the certificate and key exist
	cert := filepath.Join(path, tlsCertFile)
	if exists, _ = utils.FileExists(cert); !exists {
		return nil, errors.New("TLS certificate not found: " + tlsCertFile)
	}
	key := filepath.Join(path, tlsKeyFile)
	if exists, _ = utils.FileExists(key); !exists {
		return nil, errors.New("TLS key not found: " + tlsKeyFile)
	}

	// Load the certificates initially
	tlsCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	return &tlsCertProvider{
		tlsCert: &tlsCert,
		path:    path,
		cert:    cert,
		key:     key,
	}, nil
}

// GetCertificateFn returns a function that can be used as the GetCertificate property in a tls.Config object.
func (p *tlsCertProvider) GetCertificateFn() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		p.lock.RLock()
		defer p.lock.RUnlock()

		return p.tlsCert, nil
	}
}

// Reload the certificate from disk.
func (p *tlsCertProvider) Reload() error {
	tlsCert, err := tls.LoadX509KeyPair(p.cert, p.key)
	if err != nil {
		return err
	}

	p.SetTLSCert(&tlsCert)

	return nil
}

// SetTLSCert updates the TLS certificate object.
func (p *tlsCertProvider) SetTLSCert(tlsCert *tls.Certificate) {
	p.lock.Lock()
	p.tlsCert = tlsCert
	p.lock.Unlock()
}

// Watch starts watching (in background) for changes to the TLS certificate and key on disk, and triggers a reload when that happens.
func (p *tlsCertProvider) Watch(ctx context.Context, logger *zerolog.Logger) error {
	watcher, err := utils.WatchFolder(ctx, p.path, logger)
	if err != nil {
		return fmt.Errorf("failed to start watching for changes on disk: %w", err)
	}

	// Start the background watcher
	go func() {
		var reloadErr error
		for {
			select {
			case <-watcher:
				// Reload
				logger.Info().Msg("Found changes in folder containing TLS certificates; will reload certificates")
				reloadErr = p.Reload()
				if reloadErr != nil {
					// Log errors only
					logger.Error().
						AnErr("error", reloadErr).
						Msg("Failed to load updated TLS certificates from disk")
					continue
				}
				logger.Info().Msg("TLS certificates have been reloaded")

			case <-ctx.Done():
				// Stop on context cancellation
				return
			}
		}
	}()

	return nil
}
