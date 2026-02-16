run "basic_deploy" {

  assert {
    condition     = module.cos_registration_server_k8s.app_name == "cos-registration-server"
    error_message = "app_name did not match expected default value"
  }

  # Test requires integration endpoints - check count
  assert {
    condition     = length(module.cos_registration_server_k8s.requires) == 8
    error_message = "Expected 6 required integration endpoints"
  }

  # Test requires integration endpoints - check specific keys
  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.requires), "catalogue")
    error_message = "requires output is missing 'catalogue' endpoint"
  }

  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.requires), "ingress")
    error_message = "requires output is missing 'ingress' endpoint"
  }

  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.requires), "logging")
    error_message = "requires output is missing 'logging' endpoint"
  }

  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.requires), "tracing")
    error_message = "requires output is missing 'tracing' endpoint"
  }

  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.requires), "logging_alerts_devices")
    error_message = "requires output is missing 'logging_alerts_devices' endpoint"
  }

  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.requires), "send_remote_write_alerts_devices")
    error_message = "requires output is missing 'send_remote_write_alerts_devices' endpoint"
  }

  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.requires), "database")
    error_message = "requires output is missing 'database' endpoint"
  }

  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.requires), "certificates")
    error_message = "requires output is missing 'certificates' endpoint"
  }

  # Test requires integration endpoints - check exact values
  assert {
    condition     = module.cos_registration_server_k8s.requires["catalogue"] == "catalogue"
    error_message = "requires.catalogue endpoint did not match expected value"
  }

  assert {
    condition     = module.cos_registration_server_k8s.requires["ingress"] == "ingress"
    error_message = "requires.ingress endpoint did not match expected value"
  }

  assert {
    condition     = module.cos_registration_server_k8s.requires["logging"] == "logging"
    error_message = "requires.logging endpoint did not match expected value"
  }

  assert {
    condition     = module.cos_registration_server_k8s.requires["tracing"] == "tracing"
    error_message = "requires.tracing endpoint did not match expected value"
  }

  assert {
    condition     = module.cos_registration_server_k8s.requires["logging_alerts_devices"] == "logging-alerts-devices"
    error_message = "requires.logging_alerts_devices endpoint did not match expected value"
  }

  assert {
    condition     = module.cos_registration_server_k8s.requires["send_remote_write_alerts_devices"] == "send-remote-write-alerts-devices"
    error_message = "requires.send_remote_write_alerts_devices endpoint did not match expected value"
  }

  assert {
    condition     = module.cos_registration_server_k8s.requires["database"] == "database"
    error_message = "requires.database endpoint did not match expected value"
  }

  assert {
    condition     = module.cos_registration_server_k8s.requires["certificates"] == "tls-certificates"
    error_message = "requires.certificates endpoint did not match expected value"
  }

  # Test provides integration endpoints - check count
  assert {
    condition     = length(module.cos_registration_server_k8s.provides) == 5
    error_message = "Expected 5 provided integration endpoints"
  }

  # Test provides integration endpoints - check specific keys
  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.provides), "grafana_dashboard")
    error_message = "provides output is missing 'grafana_dashboard' endpoint"
  }

  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.provides), "grafana_dashboard_devices")
    error_message = "provides output is missing 'grafana_dashboard_devices' endpoint"
  }

  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.provides), "probes")
    error_message = "provides output is missing 'probes' endpoint"
  }

  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.provides), "probes_devices")
    error_message = "provides output is missing 'probes_devices' endpoint"
  }

  assert {
    condition     = contains(keys(module.cos_registration_server_k8s.provides), "auth_devices_keys")
    error_message = "provides output is missing 'auth_devices_keys' endpoint"
  }

  # Test provides integration endpoints - check exact values
  assert {
    condition     = module.cos_registration_server_k8s.provides["grafana_dashboard"] == "grafana-dashboard"
    error_message = "provides.grafana_dashboard endpoint did not match expected value"
  }

  assert {
    condition     = module.cos_registration_server_k8s.provides["grafana_dashboard_devices"] == "grafana-dashboard-devices"
    error_message = "provides.grafana_dashboard_devices endpoint did not match expected value"
  }

  assert {
    condition     = module.cos_registration_server_k8s.provides["probes"] == "probes"
    error_message = "provides.probes endpoint did not match expected value"
  }

  assert {
    condition     = module.cos_registration_server_k8s.provides["probes_devices"] == "probes-devices"
    error_message = "provides.probes_devices endpoint did not match expected value"
  }

  assert {
    condition     = module.cos_registration_server_k8s.provides["auth_devices_keys"] == "auth-devices-keys"
    error_message = "provides.auth_devices_keys endpoint did not match expected value"
  }

}
