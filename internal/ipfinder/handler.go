package ipfinder

import (
	"net"
	"net/http"

	"github.com/ski-company/traefik-xrealip-fixer/internal/helper"
	"github.com/ski-company/traefik-xrealip-fixer/internal/logger"
	"github.com/ski-company/traefik-xrealip-fixer/internal/providers"
	"github.com/ski-company/traefik-xrealip-fixer/internal/providers/cloudflare"
	"github.com/ski-company/traefik-xrealip-fixer/internal/providers/cloudfront"
)

// ServeHTTP is the middleware entrypoint.
func (ipFinder *Ipfinder) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	trustResult := ipFinder.trust(req.RemoteAddr, req)

	if trustResult.isFatal {
		http.Error(rw, "Unknown source", http.StatusInternalServerError)
		return
	}
	if trustResult.isError {
		http.Error(rw, "Unknown source", http.StatusBadRequest)
		return
	}
	if trustResult.directIP == "" {
		http.Error(rw, "Unknown source", http.StatusUnprocessableEntity)
		return
	}

	helper.CleanInboundForwardingHeaders(req.Header)

	socketIP := helper.ParseSocketIP(req.RemoteAddr)
	matched := providers.Unknown
	if ipFinder.ipInProvider(providers.Cloudflare, socketIP) {
		matched = providers.Cloudflare
	} else if ipFinder.ipInProvider(providers.Cloudfront, socketIP) {
		matched = providers.Cloudfront
	}

	if trustResult.trusted {
		req.Header.Set(helper.XRealipFixerTrusted, "yes")
		switch matched {
		case providers.Cloudflare:
			req.Header.Set(helper.XRealipFixerProvider, "cloudflare")
		case providers.Cloudfront:
			req.Header.Set(helper.XRealipFixerProvider, "cloudfront")
		default:
			req.Header.Set(helper.XRealipFixerProvider, "unknown")
		}

		var clientIPHeaderName string
		switch ipFinder.provider {
		case providers.Auto:
			if matched == providers.Cloudflare && req.Header.Get(cloudflare.ClientIPHeaderName) != "" {
				clientIPHeaderName = cloudflare.ClientIPHeaderName
			} else if matched == providers.Cloudfront && req.Header.Get(cloudfront.ClientIPHeaderName) != "" {
				clientIPHeaderName = cloudfront.ClientIPHeaderName
			}
		default:
			clientIPHeaderName = ipFinder.clientIPHeaderName
		}

		var clientIP string
		if clientIPHeaderName != "" {
			clientIP = helper.ExtractClientIP(req.Header.Get(clientIPHeaderName))
			if net.ParseIP(clientIP) == nil {
				clientIP = ""
			}
		}
		if clientIP == "" {
			clientIP = trustResult.directIP
		}

		helper.AppendXFF(req.Header, clientIP)
		req.Header.Set(helper.XRealIP, clientIP)

	} else {
		logger.LogInfo("Untrusted request from", "remote", socketIP)
		req.Header.Set(helper.XRealipFixerTrusted, "no")
		req.Header.Set(helper.XRealipFixerProvider, "unknown")

		switch ipFinder.provider {
		case providers.Cloudflare, providers.Auto:
			req.Header.Del(cloudflare.ClientIPHeaderName)
		case providers.Cloudfront:
			req.Header.Del(cloudfront.ClientIPHeaderName)
		}

		useIP := trustResult.directIP
		if useIP == "" {
			useIP = socketIP
		}

		helper.AppendXFF(req.Header, useIP)
		req.Header.Set(helper.XRealIP, useIP)
	}

	ipFinder.next.ServeHTTP(rw, req)
}

// ipInProvider checks if ipStr is contained in a provider bucket (thread-safe).
func (ipFinder *Ipfinder) ipInProvider(prov providers.Provider, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ipFinder.contains(prov, ip)
}
