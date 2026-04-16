# ── Detour sidecar add to your existing google_cloud_run_v2_service ─────────
#
# Two changes only. Everything else in your resource stays as-is.
#
# Variables to add:
#   variable "detour_enabled"    { type = bool;   default = false }
#   variable "detour_broker_url" { type = string; default = ""    }
#
# Also ensure your template block has:
#   execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
# ─────────────────────────────────────────────────────────────────────────────

# Change 1: make your existing ports block conditional.
#
# Before: ports { container_port = 8080 }
# After:
dynamic "ports" {
  for_each = var.detour_enabled ? [] : [1]
  content {
    container_port = 8080
  }
}

# Change 2: add this inside your template block alongside your app container.
dynamic "containers" {
  for_each = var.detour_enabled ? [1] : []
  content {
    name  = "detour-sidecar"
    image = "ghcr.io/riain0/detour-sidecar:latest"

    ports { container_port = 8081 }

    env { name = "APP_UPSTREAM";         value = "localhost:8080" }
    env { name = "DETOUR_BROKER_URL";    value = var.detour_broker_url }
    env { name = "DETOUR_SERVICE_NAME";  value = "<your-service-name>" }
    env { name = "DETOUR_AUTH_MODE";     value = "session-id" }
  }
}
