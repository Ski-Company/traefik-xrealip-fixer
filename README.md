<p align="left">
  <img src=".assets/traefik-xrealip-fixer-logo-transparent.png" alt="traefik-xrealip-fixer logo" width="220" />
</p>

# traefik-xrealip-fixer

**traefik-xrealip-fixer** is a Traefik middleware that reliably reconstructs the true client IP address in environments where multiple proxies, CDNs, and load balancers interfere with or override IP-related headers.

Modern infrastructures often include layers such as Cloudflare, AWS ALB/NLB, Traefik ingress controllers, reverse proxies, and internal mesh components. Each hop may append or modify values in `X-Forwarded-For` or `X-Real-IP`, making it difficult — and sometimes impossible — for backend services to determine the actual originating client IP.

This middleware solves that problem by implementing a robust, anti-spoofing IP extraction algorithm:

- Automatically handles Cloudflare headers (`CF-Connecting-IP`, `True-Client-IP`)
- Fully compatible with AWS ALB/NLB and other proxy layers
- Extracts the correct client IP from `X-Forwarded-For` using **reverse indexing** (from the end)
- Ignores spoofed, private, reserved, or internal IP ranges
- Overwrites or sets `X-Real-IP` with a clean, verified public IP address

By restoring an accurate and trustworthy client source address, `traefik-xrealip-fixer` improves access logs, rate limiting, WAF rules, fraud detection, and any IP‑based decision system.

---

## ✨ Features

- 🔒 Anti-spoofing logic
- 🔍 Smart backward scanning of X-Forwarded-For
- ☁️ Cloudflare support out of the box
- 🟢 Compatible with Traefik v3 middleware chain
- 🚀 Zero configuration required

---

## 📦 Installation

### Static configuration (TOML)

```toml
[experimental.plugins.traefik-xrealip-fixer]
  moduleName = "github.com/ski-company/traefik-xrealip-fixer"
  version = "v1.0.0"
```

### Static configuration (YAML)

```yaml
experimental:
  plugins:
    traefik-xrealip-fixer:
      moduleName: github.com/ski-company/traefik-xrealip-fixer
      version: v1.0.0
```

### Enable middleware

```yaml
http:
  middlewares:
    realip:
      plugin:
        traefik-xrealip-fixer: {}
```

---

## 🧩 Usage Example

```yaml
http:
  routers:
    myapp:
      rule: "Host(`example.com`)"
      service: myapp-svc
      middlewares:
        - realip

  middlewares:
    realip:
      plugin:
        traefik-xrealip-fixer: {}
```

---

## ⚙️ Options

```yaml
plugin:
  traefik-xrealip-fixer:
    trustCloudflare: true
    trustXForwardedFor: true
    privateRanges:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
      - "172.16.0.0/12"
      - "fc00::/7"
```

---

## 🔍 How it Works

1. Prefer Cloudflare headers when present  
2. Otherwise parse `X-Forwarded-For`  
3. Walk from the **end** of the list (closest proxy)  
4. Skip private/reserved IPs  
5. First public IP found is used as the real client IP  
6. Set/override `X-Real-IP`

---

## 🛡 Security Considerations

- Protects against spoofed first-hop IPs  
- Only selects valid public IP addresses  
- Safe defaults inspired by common proxy/CDN behavior  

---

## 🧪 Development

```bash
git clone https://github.com/ski-company/traefik-xrealip-fixer
cd traefik-xrealip-fixer
go build ./...
go test ./...
```

---

## 📜 License

MIT or Apache 2.0

---

## 🤝 Contributing

PRs, issues, and ideas are welcome!
