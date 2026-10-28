# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    sidegate = {
      source  = "s-nof3ar/sidegate"
      version = "~> 0.1"
    }
  }
}

# The token is read from $SIDEGATE_TOKEN; create one in the admin UI under
# "API tokens".
provider "sidegate" {
  endpoint = "https://apps.example.com"
}

# Readable names for Entra ID groups (object IDs).
resource "sidegate_group" "developers" {
  group_id = "33333333-3333-3333-3333-333333333333"
  name     = "developers"
}

resource "sidegate_group" "platform_admins" {
  group_id = "22222222-2222-2222-2222-222222222222"
  name     = "platform-admins"
}

resource "sidegate_app" "grafana" {
  name        = "grafana"
  title       = "Grafana"
  description = "Dashboards and metrics"
  icon        = "https://grafana.com/static/assets/img/fav32.png"
  category    = "Monitoring"
  upstream    = "http://grafana.monitoring.svc.cluster.local:3000"

  allowed_groups = [
    sidegate_group.developers.group_id,
    sidegate_group.platform_admins.group_id,
  ]
  public_paths = ["/api/health", "/public/*"]
}

resource "sidegate_app" "argocd" {
  name                 = "argocd"
  title                = "Argo CD"
  category             = "Platform/Delivery"
  upstream             = "https://argocd-server.argocd.svc.cluster.local"
  insecure_skip_verify = true
  require_mfa          = true
  max_auth_age_minutes = 60
  host_header          = "argocd.internal.example.com"
  allowed_groups       = [sidegate_group.platform_admins.group_id]
}

# A Windows server reachable as a remote desktop (browser or sidegate).
resource "sidegate_app" "jumphost" {
  name                 = "jumphost"
  title                = "Admin jump host"
  category             = "Desktops"
  upstream             = "rdp://jump01.corp.example.com:3389?security=nla&domain=CORP"
  allowed_groups       = [sidegate_group.platform_admins.group_id]
  require_mfa          = true
  max_auth_age_minutes = 60
}

# A Linux bastion: terminal in the browser, or `sidegate ssh` / ProxyCommand.
resource "sidegate_app" "bastion" {
  name           = "bastion"
  title          = "Bastion"
  category       = "Servers"
  upstream       = "ssh://bastion.corp.example.com?host-key=ecdsa-sha2-nistp256%20AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY="
  allowed_groups = [sidegate_group.platform_admins.group_id]
  require_mfa    = true
}

resource "sidegate_app" "status" {
  name     = "status"
  upstream = "http://status-page.default.svc:8080"
  public   = true
}

output "grafana_url" {
  value = sidegate_app.grafana.url
}
