# detour

Route live cloud traffic to your local machine. No VPN, no SSH tunnels, no changes to your app code.

Detour adds a lightweight sidecar to your cloud service. Requests that include an `X-Route-To` header are relayed through an outbound tunnel to your machine. Everyone else hits the normal cloud app.

```
Browser / curl
  │
  ▼
detour-sidecar  (:8081, ingress)
  ├─ no X-Route-To header  ──────────────────────▶  your app  (:8080)
  └─ X-Route-To: <session> ──▶  detour-broker  ──▶  detour agent  ──▶  localhost:3000
                                  (gRPC relay)         (your machine)
```

## Who does what

**Platform / ops team** — set up once per environment:
- Deploy the broker (one instance, shared by the team)
- Add the sidecar container to each service you want to be routable
- Set `DETOUR_SERVICE_NAME` on each sidecar so sessions can't be cross-routed

**Developer** — on their machine:
- Run `detour start` (or use the VS Code extension)
- Copy the printed `X-Route-To` header
- Add it to requests in their browser, Postman, or any HTTP client

No firewall rules, no inbound ports. The agent makes an outbound connection to the broker.

---

## Platform team: deploying the broker

The broker is a small gRPC relay server. Deploy it once and share it across services.

```bash
docker run -p 50051:50051 ghcr.io/riain0/detour-broker:latest
```

**With Redis (recommended)** — sessions survive broker restarts and the broker logs which backend it is using at startup:

```bash
docker run -p 50051:50051 \
  -e REDIS_URL=redis://your-redis:6379 \
  ghcr.io/riain0/detour-broker:latest
```

Without Redis the broker falls back to in-memory automatically.

### Broker configuration

| Env var | Default | Description |
|---|---|---|
| `PORT` | `8080` | gRPC listen port |
| `REDIS_URL` | `redis://127.0.0.1:6379` | Session storage. Falls back to in-memory if unreachable |
| `DETOUR_SESSION_TTL_SECS` | `28800` | Session lifetime in seconds (8h) |
| `DETOUR_AUTH_MODE` | `session-id` | `session-id` or `signed-token` |

### Broker IaC

Terraform snippets are in [`deploy/terraform/`](deploy/terraform/).

**GCP Cloud Run** — [`deploy/terraform/gcp/broker.tf`](deploy/terraform/gcp/broker.tf)

**AWS Fargate** — [`deploy/terraform/aws/broker.tf`](deploy/terraform/aws/broker.tf) (requires an ACM certificate — ALB needs HTTPS for gRPC)

---

## Platform team: adding the sidecar

The sidecar runs alongside your app container and intercepts matching requests. Your service URL does not change.

Set `DETOUR_SERVICE_NAME` to the same name developers will use when starting the agent. This prevents sessions registered for `payments-api` from accidentally routing to a `user-api` sidecar.

### Sidecar configuration

| Env var | Default | Description |
|---|---|---|
| `DETOUR_BROKER_URL` | `http://localhost:50051` | Broker address |
| `APP_UPSTREAM` | `localhost:8080` | App container address |
| `DETOUR_LISTEN_PORT` / `PORT` | `8000` | Sidecar listen port |
| `DETOUR_SERVICE_NAME` | `""` | Only route sessions registered under this name |
| `DETOUR_AUTH_MODE` | `session-id` | Must match the broker |

### Sidecar IaC

**GCP Cloud Run** — add to your existing `google_cloud_run_v2_service` from [`deploy/terraform/gcp/sidecar.tf`](deploy/terraform/gcp/sidecar.tf):

```hcl
# 1. Make your existing ports block conditional
dynamic "ports" {
  for_each = var.detour_enabled ? [] : [1]
  content { container_port = 8080 }
}

# 2. Add the sidecar container
dynamic "containers" {
  for_each = var.detour_enabled ? [1] : []
  content {
    name  = "detour-sidecar"
    image = "ghcr.io/riain0/detour-sidecar:latest"
    ports { container_port = 8081 }
    env { name = "APP_UPSTREAM";        value = "localhost:8080" }
    env { name = "DETOUR_BROKER_URL";   value = local.detour_broker_url }
    env { name = "DETOUR_SERVICE_NAME"; value = "<your-service-name>" }
  }
}
```

Also set `execution_environment = "EXECUTION_ENVIRONMENT_GEN2"` on your template (required for multi-container).

**AWS Fargate** — [`deploy/terraform/aws/sidecar.tf`](deploy/terraform/aws/sidecar.tf):

```hcl
container_definitions = jsonencode(concat(
  [{ name = "app", ... }],
  var.detour_enabled ? [{
    name  = "detour-sidecar"
    image = "ghcr.io/riain0/detour-sidecar:latest"
    portMappings = [{ containerPort = 8081 }]
    environment = [
      { name = "APP_UPSTREAM",        value = "localhost:8080" },
      { name = "DETOUR_BROKER_URL",   value = var.detour_broker_url },
      { name = "DETOUR_SERVICE_NAME", value = "<your-service-name>" },
      { name = "DETOUR_LISTEN_PORT",  value = "8081" }
    ]
  }] : []
))

resource "aws_lb_target_group" "app" {
  port = var.detour_enabled ? 8081 : 8080
}
```

Set `detour_enabled = false` in production — the sidecar is never deployed and your service is unchanged.

---

## Developer: routing traffic to your machine

### Installation

Pre-built binaries for Linux and macOS are on the [releases page](https://github.com/riain0/detour/releases).

**macOS (Apple Silicon):**
```bash
curl -L https://github.com/riain0/detour/releases/latest/download/detour-latest-aarch64-apple-darwin.tar.gz | tar xz
sudo mv detour /usr/local/bin/
```

**VS Code extension** — install Detour from the marketplace. The extension downloads the CLI automatically on first use (macOS and Linux).

**From source** (requires Rust 1.75+):
```bash
cargo install --path crates/cli
```

### Starting a session

```bash
detour start --route my-api:3000 --broker https://broker.example.com
```

```
  Detour v0.1.0
  Connecting to https://broker.example.com ...

  my-api  →  X-Route-To: a3f8c2d1-9e4b-4f1a-8c7d-2b5e6f0a1c3d  →  localhost:3000

  Status: connected
```

Add the printed header to your requests:

```bash
curl -H "X-Route-To: a3f8c2d1-9e4b-4f1a-8c7d-2b5e6f0a1c3d" https://my-service.example.com/api/orders
```

That request is relayed through the broker to `localhost:3000` on your machine. Everyone else hits the normal cloud app.

### Multiple services

```bash
detour start \
  --route payments-api:3001 \
  --route user-api:3002 \
  --broker https://broker.example.com
```

Each route gets its own session ID and independent tunnel.

### CLI reference

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--route SERVICE:PORT` | | | Service name and local port. Repeatable |
| `--broker URL` | `DETOUR_BROKER_URL` | `http://localhost:50051` | Broker URL |
| `--output` | | `human` | `human` or `json` (for tooling integrations) |

### Local status

```bash
curl http://localhost:29876/status
```

```json
{
  "version": "1",
  "status": "connected",
  "broker_url": "https://broker.example.com",
  "sessions": [
    { "service": "payments-api", "session_id": "a3f8c2d1-...", "port": 3001, "status": "connected" },
    { "service": "user-api",     "session_id": "b7e2d4f9-...", "port": 3002, "status": "connected" }
  ]
}
```

---

## Docker images

Published to GHCR on every release:

| Image | Description |
|---|---|
| `ghcr.io/riain0/detour-broker:latest` | gRPC relay broker |
| `ghcr.io/riain0/detour-sidecar:latest` | HTTP sidecar proxy |

Tags: `latest` and `vX.Y.Z` for pinned versions.

## License

MIT
