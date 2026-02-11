data "juju_model" "model" {
  name  = "testing"
  owner = "admin"
}

variable "channel" {
  description = "The channel to use when deploying a charm"
  type        = string
  default     = "latest/edge"
}

terraform {
  required_providers {
    juju = {
      version = "~> 1.0"
      source  = "juju/juju"
    }
  }
}

provider "juju" {}

module "cos_registration_server_k8s" {
  app_name   = "cos-registration-server"
  source     = "./.."
  channel    = var.channel
  model_uuid = data.juju_model.model.uuid
  units      = 1
}
