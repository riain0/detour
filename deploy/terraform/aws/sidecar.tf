# ── Detour sidecar AWS Fargate (ECS) ───────────────────────────────────────
#
# Two changes to your existing ECS task definition and load balancer.
#
# Variables to add:
#   variable "detour_enabled"    { type = bool;   default = false }
#   variable "detour_broker_url" { type = string; default = ""    }
# ─────────────────────────────────────────────────────────────────────────────

# Change 1: in your aws_ecs_task_definition, update container_definitions
# to conditionally include the sidecar alongside your app container.
#
# The sidecar takes the inbound port (8081); your app stays on 8080 via localhost.
#
# Before:
#   container_definitions = jsonencode([{ name = "app", ... portMappings = [{ containerPort = 8080 }] }])
#
# After:
resource "aws_ecs_task_definition" "app" {
  # ... your existing arguments unchanged ...

  container_definitions = jsonencode(concat(
    [
      {
        name      = "app"
        image     = var.app_image
        essential = true
        # App stays on 8080 sidecar reaches it via localhost
        portMappings = [{ containerPort = 8080, protocol = "tcp" }]
        # ... rest of your existing app container config ...
      }
    ],
    var.detour_enabled ? [
      {
        name      = "detour-sidecar"
        image     = "ghcr.io/riain0/detour-sidecar:latest"
        essential = false
        portMappings = [{ containerPort = 8081, protocol = "tcp" }]
        environment = [
          { name = "APP_UPSTREAM",         value = "localhost:8080" },
          { name = "DETOUR_BROKER_URL",    value = var.detour_broker_url },
          { name = "DETOUR_SERVICE_NAME",  value = "<your-service-name>" },
          { name = "DETOUR_AUTH_MODE",     value = "session-id" },
          { name = "DETOUR_LISTEN_PORT",   value = "8081" }
        ]
      }
    ] : []
  ))
}

# Change 2: point your load balancer target group at the sidecar port when
# detour is enabled, your app port when it is not.
#
# Before:
#   port = 8080
#
# After:
resource "aws_lb_target_group" "app" {
  # ... your existing arguments ...
  port = var.detour_enabled ? 8081 : 8080
}
