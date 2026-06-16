package anytls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"golang.org/x/crypto/acme/autocert"
)

var ErrTLSConfigRequired = errors.New("anytls tls config with certificate provider is required")

type tlsConfigContextKey struct{}

type autocertTLSResources struct {
	tlsConfig  *tls.Config
	httpServer *http.Server
}

type certificateGetter func(*tls.ClientHelloInfo) (*tls.Certificate, error)

func WithTLSConfig(ctx context.Context, tlsConfig *tls.Config) context.Context {
	return context.WithValue(ctx, tlsConfigContextKey{}, tlsConfig)
}

func tlsConfigFromContext(ctx context.Context) (*tls.Config, error) {
	tlsConfig, _ := ctx.Value(tlsConfigContextKey{}).(*tls.Config)
	return normalizeTLSConfig(tlsConfig)
}

func normalizeTLSConfig(tlsConfig *tls.Config) (*tls.Config, error) {
	if tlsConfig == nil {
		return nil, ErrTLSConfigRequired
	}
	tlsConfig = tlsConfig.Clone()
	if len(tlsConfig.Certificates) == 0 && tlsConfig.GetCertificate == nil && tlsConfig.GetConfigForClient == nil {
		return nil, ErrTLSConfigRequired
	}
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	return tlsConfig, nil
}

func newAutocertTLSResources(sni string, onRenew func()) (*autocertTLSResources, error) {
	sni = strings.TrimSpace(sni)
	if sni == "" {
		return nil, fmt.Errorf("empty anytls TLS SNI")
	}
	manager := &autocert.Manager{
		Cache:      autocert.DirCache("tls"),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(sni),
	}
	return &autocertTLSResources{
		tlsConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: renewingCertificateGetter(sni, manager.GetCertificate, 5*time.Second, onRenew),
		},
		httpServer: &http.Server{Addr: ":80", Handler: manager.HTTPHandler(nil)},
	}, nil
}

func renewingCertificateGetter(sni string, getCertificate certificateGetter, renewAfter time.Duration, onRenew func()) certificateGetter {
	return func(info *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
		var renewing atomic.Bool
		timer := time.AfterFunc(renewAfter, func() {
			renewing.Store(true)
			log.Warn("We are now renewing the certificate for %v.", sni)
		})
		defer timer.Stop()
		defer func() {
			if !renewing.Load() {
				return
			}
			if err != nil {
				log.Warn("Failed to renew the certificate for %v: %v", sni, err)
				return
			}
			log.Warn("The certificate for %v is renewed successfully.", sni)
			if onRenew != nil {
				onRenew()
			}
		}()
		return getCertificate(info)
	}
}
