package ipfinder

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ski-company/traefik-xrealip-fixer/internal/logger"
	"github.com/ski-company/traefik-xrealip-fixer/internal/providers"
	"github.com/ski-company/traefik-xrealip-fixer/internal/providers/auto"
	"github.com/ski-company/traefik-xrealip-fixer/internal/providers/cloudflare"
	"github.com/ski-company/traefik-xrealip-fixer/internal/providers/cloudfront"
)

// refreshProvidersIPSLoop periodically refreshes the allowlists until ctx is done.
func (ipFinder *Ipfinder) refreshProvidersIPSLoop(ctx context.Context, interval time.Duration) {
	jitter := time.Duration(int64(time.Second) * (int64(time.Now().UnixNano()) % 7))
	t := time.NewTimer(interval + jitter)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := ipFinder.refreshProvidersIPS(); err != nil {
				logger.LogWarn("periodic providers IPS refresh failed", "error", err.Error())
			} else {
				cfCIDRsQty, cfnCIDRsQty := ipFinder.counts()
				logger.LogInfo("providers IPS refreshed", "cloudflare", fmt.Sprintf("%d", cfCIDRsQty), "cloudfront", fmt.Sprintf("%d", cfnCIDRsQty))
			}
			t.Reset(interval)
		}
	}
}

// refreshProvidersIPS fetches defaults + merges user-supplied CIDRs, then swaps atomically.
func (ipFinder *Ipfinder) refreshProvidersIPS() error {
	var autoCIDRs, cfCIDRs, cfnCIDRs []string
	switch ipFinder.provider {
	case providers.Auto:
		autoCIDRs = auto.TrustedIPS()
	case providers.Cloudflare:
		cfCIDRs  = cloudflare.TrustedIPS()
	case providers.Cloudfront:
		cfnCIDRs = cloudfront.TrustedIPS()
	}

	newMap := make(map[providers.Provider][]*net.IPNet)
	add := func(p providers.Provider, cidrs []string) {
		for _, v := range cidrs {
			c := strings.TrimSpace(v)
			if c == "" {
				continue
			}
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				continue
			}
			newMap[p] = append(newMap[p], n)
		}
	}

	if len(autoCIDRs) > 0 {
		add(providers.Auto, autoCIDRs)
	} else {
		if len(cfCIDRs) > 0 {
			add(providers.Cloudflare, cfCIDRs)
		}
		if len(cfnCIDRs) > 0 {
			add(providers.Cloudfront, cfnCIDRs)
		}
	}

	ipFinder.mu.Lock()
	ipFinder.TrustIP = newMap
	ipFinder.mu.Unlock()

	return nil
}

// counts the number of CIDRs loaded per provider.
func (ipFinder *Ipfinder) counts() (cfCIDRsQty, cfnCIDRsQty int) {
	ipFinder.mu.RLock()
	defer ipFinder.mu.RUnlock()
	cfCIDRsQty = len(ipFinder.TrustIP[providers.Cloudflare])
	cfnCIDRsQty = len(ipFinder.TrustIP[providers.Cloudfront])
	return
}

// helper: membership check with lock
func (ipFinder *Ipfinder) contains(prov providers.Provider, ip net.IP) bool {
	ipFinder.mu.RLock()
	nets := ipFinder.TrustIP[prov]
	ipFinder.mu.RUnlock()
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// trust decides whether the REMOTE socket IP belongs to a trusted edge network.
// In Auto mode we treat trust as the UNION of Cloudflare + CloudFront.
func (ipFinder *Ipfinder) trust(remote string, _ *http.Request) *TrustResult {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return &TrustResult{isError: true}
	}

	switch ipFinder.provider {
	case providers.Cloudflare:
		if ipFinder.contains(providers.Cloudflare, ip) {
			return &TrustResult{trusted: true, directIP: ip.String()}
		}
	case providers.Cloudfront:
		if ipFinder.contains(providers.Cloudfront, ip) {
			return &TrustResult{trusted: true, directIP: ip.String()}
		}
	case providers.Auto:
		if ipFinder.contains(providers.Cloudflare, ip) || ipFinder.contains(providers.Cloudfront, ip) {
			return &TrustResult{trusted: true, directIP: ip.String()}
		}
	}
	return &TrustResult{trusted: false, directIP: ip.String()}
}
