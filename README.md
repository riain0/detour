# detour

Route live cloud traffic to your local machine. No VPN, no SSH tunnels, no changes to your app container.

Detour adds a sidecar to your cloud service that inspects HTTP headers. Requests with an `X-Route-To` header are relayed through a gRPC tunnel to your machine. Everything else passes straight through to your app with zero overhead.

Works with Cloud Run, AWS Fargate, or any HTTP service you can put a sidecar in front of.

## How it works

```
Browser / curl
  │
  ▼
detour-sidecar  (:8081, ingress)
  ├─ no X-Route-To header  ──────────────────────▶  your app container  (:8080)
  └─ X-Route-To: <session> ──▶  detour-broker  ──▶  detour agent  ──▶  localhost:3000
                                  (gRPC relay)         (your machine)
```

`detour-sidecar` runs alongside your app container and is invisible to clients the service URL does not change. `detour-broker` is a small gRPC relay server deployed once per team. `detour start` runs on your machine and opens an outbound tunnel to the broker no inbound ports or firewall rules required.

## Installation

Pre-built binaries for Linux and macOS are on the [releases page](https://github.com/riain0/detour/releases).

```bash
# macOS (Apple Silicon)
curl -L https://github.com/riain0/detour/releases/latest/download/detour-latest-aarch64-apple-darwin.tar.gz | tar xz
sudo mv detour /usr/local/bin/
```

To build from source (requires Rust 1.75+):

```bash
git clone https://github.com/riain0/detour
cd detour
cargo install --path crates/cli
```

## Quick start

**1. Deploy the broker** (once per team / environment see [IaC](#deploying-with-iac)):

```bash
docker run -p 50051:50051 ghcr.io/riain0/detour-broker:latest
```

**2. Add the sidecar** to your service (see [IaC](#deploying-with-iac) for Terraform snippets).

**3. Start routing to your machine:**

```bash
detour start --route my-api:3000 --broker https://broker.example.com
```

```
  Detour v0.1.0
  Connecting to https://broker.example.com ...

  my-api  →  X-Route-To: a3f8c2d1-9e4b-4f1a-8c7d-2b5e6f0a1c3d  →  localhost:3000

  Status: connected
```

Add the printed header to your requests and they will be routed to `localhost:3000` on your machine:

```bash
curl -H "X-Route-To: a3f8c2d1-9e4b-4f1a-8c7d-2b5e6f0a1c3d" https://my-service.example.com/api/orders
```

**4. Route multiple services at once:**

```bash
detour start \
  --route payments-api:3001 \
  --route user-api:3002 \
  --broker https://broker.example.com
```

Each route gets its own session ID and tunnel.

## Deploying with IaC

Terraform snippets for adding detour to an existing service are in [`deploy/terraform/`](deploy/terraform/).

### GCP Cloud Run

**Deploy the broker** add [`deploy/terraform/gcp/broker.tf`](deploy/terraform/gcp/broker.tf) to your dev environment config.

**Add the sidecar** two additions to your existing `google_cloud_run_v2_service` from [`deploy/terraform/gcp/sidecar.tf`](deploy/terraform/gcp/sidecar.tf):

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

### AWS Fargate

**Deploy the broker** add [`deploy/terraform/aws/broker.tf`](deploy/terraform/aws/broker.tf). Requires an ACM certificate ALB needs HTTPS for gRPC.

**Add the sidecar** two changes to your task definition and target group from [`deploy/terraform/aws/sidecar.tf`](deploy/terraform/aws/sidecar.tf):

```hcl
# 1. Add the sidecar to container_definitions
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

# 2. Point the load balancer at the sidecar port when enabled
resource "aws_lb_target_group" "app" {
  port = var.detour_enabled ? 8081 : 8080
}
```

In both cases, set `detour_enabled = false` in prod the sidecar is never deployed and your service is unchanged.

## Docker images

Published to GHCR on every release:

| Image | Description |
|---|---|
| `ghcr.io/riain0/detour-broker:latest` | gRPC relay broker |
| `ghcr.io/riain0/detour-sidecar:latest` | HTTP sidecar proxy |

Tags: `latest` and `vX.Y.Z` for pinned versions.

## Configuration

### Broker

| Env var | Default | Description |
|---|---|---|
| `PORT` | `8080` | gRPC listen port |
| `REDIS_URL` | `redis://127.0.0.1:6379` | Session storage. Falls back to in-memory if unreachable |
| `DETOUR_SESSION_TTL_SECS` | `28800` | Session lifetime (8h) |
| `DETOUR_AUTH_MODE` | `session-id` | `session-id` or `signed-token` |

### Sidecar

| Env var | Default | Description |
|---|---|---|
| `DETOUR_BROKER_URL` | `http://localhost:50051` | Broker address |
| `APP_UPSTREAM` | `localhost:8080` | App container address |
| `DETOUR_LISTEN_PORT` / `PORT` | `8000` | Sidecar listen port |
| `DETOUR_SERVICE_NAME` | `""` | If set, only routes sessions registered under this service name |
| `DETOUR_AUTH_MODE` | `session-id` | Must match the broker |

### CLI

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--route SERVICE:PORT` | | | Service name and local port to forward to. Repeatable |
| `--broker URL` | `DETOUR_BROKER_URL` | `http://localhost:50051` | Broker URL |
| `--auth-mode` | | `session-id` | `session-id` or `signed-token` |
| `--output` | | `human` | `human` or `json` |

## Service name validation

The sidecar can be scoped to a specific service by setting `DETOUR_SERVICE_NAME`. When set, session IDs registered under a different service name are rejected and the request falls through to your app preventing an agent for `payments-api` from accidentally receiving traffic intended for `user-api`.

```bash
# Agent registered as "payments-api"
detour start --route payments-api:3001 --broker https://broker.example.com

# Only the sidecar with DETOUR_SERVICE_NAME=payments-api will route this session
# A sidecar with DETOUR_SERVICE_NAME=user-api will pass it through
```

## Status endpoint

The agent exposes a local status endpoint on port 29876:

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

## JSON output

`detour start --output json` emits newline-delimited JSON, useful for IDE and browser extension integrations:

```json
{"event":"ready","ts":"1712345678Z","sessions":[{"service":"my-api","session_id":"..."}],"broker_url":"https://..."}
{"event":"status","ts":"...","status":"stopped"}
```

## Session storage

The broker uses Redis when available (recommended sessions survive restarts) and falls back to in-memory automatically. It logs which backend it is using at startup.

## License

MIT
