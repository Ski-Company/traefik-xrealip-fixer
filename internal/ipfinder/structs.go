package ipfinder

import (
	"net"
	"net/http"
	"sync"

	"github.com/ski-company/traefik-xrealip-fixer/internal/providers"
)

// Ipfinder is a plugin that overwrites the true IP.
type Ipfinder struct {
	next               http.Handler
	name               string
	provider           providers.Provider
	TrustIP            map[providers.Provider][]*net.IPNet
	clientIPHeaderName string
	cfCIDRsQty         int
	cfnCIDRsQty        int

	mu        sync.RWMutex        // guards TrustIP
	userTrust map[string][]string // keep user-supplied CIDRs for merges on refresh
}

// TrustResult for Trust IP test result.
type TrustResult struct {
	isError  bool
	trusted  bool
	directIP string
}
