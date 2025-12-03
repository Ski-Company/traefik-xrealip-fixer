package traefik_xrealip_fixer

import (
	"context"
	"net/http"

	"github.com/ski-company/traefik-xrealip-fixer/internal/config"
	"github.com/ski-company/traefik-xrealip-fixer/internal/ipfinder"
)

// Config re-exported for Traefik plugin configuration.
type Config = config.Config

// CreateConfig exposes the default configuration to Traefik.
func CreateConfig() *Config {
	return config.CreateConfig()
}

// New wires the middleware using the internal implementation.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	return ipfinder.New(ctx, next, cfg, name)
}
