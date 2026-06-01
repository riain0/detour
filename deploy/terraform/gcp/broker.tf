# ── Detour broker GCP Cloud Run ────────────────────────────────────────────
#
# Add this to your dev environment Terraform config.
# Deploy once per env all services share one broker.
#
# Variables to add:
#   variable "detour_enabled" { type = bool; default = false }
#   variable "detour_vpc_network" { type = string }
#   variable "detour_vpc_subnet"  { type = string }
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
      max_instance_count = 1
    }

    vpc_access {
      network_interfaces {
        network = var.detour_vpc_network
        subnet  = var.detour_vpc_subnet
      }
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = "ghcr.io/riain0/detour-broker:latest"

      resources {
        cpu_idle = false
      }

      # h2c = plaintext HTTP/2, required for gRPC streaming on Cloud Run
      ports {
        name           = "h2c"
        container_port = 50051
      }

      env {
        name  = "DETOUR_AUTH_MODE"
        value = "session-id"
      }

      env {
        name  = "PORT"
        value = "50051"
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
