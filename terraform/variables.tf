variable "app_name" {
  description = "Application name"
  type        = string
  nullable    = false
  default     = "cos-registration-server"
}

variable "channel" {
  description = "Charm channel"
  type        = string
  nullable    = false
  default     = "latest/edge"
}

variable "config" {
  description = "Config options as in the ones we pass in juju config"
  type        = map(string)
  default     = {}
}

# We use constraints to set AntiAffinity in K8s
# https://discourse.charmhub.io/t/pod-priority-and-affinity-in-juju-charms/4091/13?u=jose
variable "constraints" {
  description = "Constraints to be applied"
  type        = string
  default     = ""
}

variable "model" {
  description = "Model name (must be a machine model)"
  type        = string
  nullable    = false
}

variable "revision" {
  description = "Charm revision"
  type        = number
  nullable    = true
  default     = null
}

variable "units" {
  description = "Number of units"
  type        = number
  default     = 1
}

variable "resources" {
  description = "Resources used by the charm"
  type        = map(string)
  default = {
    cos-registration-server-image : "ghcr.io/canonical/cos-registration-server:dev"
  }
}

variable "storage" {
  description = "Map of storage used by the application. Defaults to 1 GB, allocated by Juju"
  type        = map(string)
  default     = {}
}
