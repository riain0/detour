# ── Detour broker GCP Cloud Run ────────────────────────────────────────────
#
# Add this to your dev environment Terraform config.
# Deploy once per env all services share one broker.
#
# Variables to add:
#   variable "detour_enabled" { type = bool; default = false }
# ─────────────────────────────────────────────────────────────────────────────

resource "google_cloud_run_v2_service" "detour_broker" {
  count    = var.detour_enabled ? 1 : 0
  name     = "detour-broker"
  location = var.region
  project  = var.project

  template {
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"

    scaling {
      min_instance_count = 1
    }

    containers {
      image = "ghcr.io/riain0/detour-broker:latest"

      # h2c = plaintext HTTP/2, required for gRPC streaming on Cloud Run
      ports {
        name           = "h2c"
        container_port = 8080
      }

      env {
        name  = "DETOUR_AUTH_MODE"
        value = "session-id"
      }
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "detour_broker_public" {
  count    = var.detour_enabled ? 1 : 0
  project  = var.project
  location = var.region
  name     = google_cloud_run_v2_service.detour_broker[0].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

locals {
  detour_broker_url = var.detour_enabled ? google_cloud_run_v2_service.detour_broker[0].uri : ""
}
