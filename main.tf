terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "4.16.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

locals {
  config = yamldecode(file("${path.module}/rules.yaml"))
}

resource "cloudflare_ruleset" "waf_ruleset" {
  for_each    = var.zone_ids
  zone_id     = each.value
  name        = "Terraform Managed WAF Rules"
  description = "WAF rules auto-updated from AbuseIPDB"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  # 添加 lifecycle 塊來處理衝突
  lifecycle {
    create_before_destroy = true
  }

  dynamic "rules" {
    for_each = { for idx, rule in local.config.rules : idx => rule }
    content {
      action      = rules.value.action
      description = rules.value.name
      expression  = rules.value.expression
      enabled     = true
      ref         = tostring(rules.key)
      
      dynamic "action_parameters" {
        for_each = contains(["skip"], rules.value.action) ? [1] : []
        content {
          products = lookup(rules.value, "products", [])
        }
      }

      dynamic "logging" {
        for_each = rules.value.action == "skip" ? [1] : []
        content {
          enabled = lookup(rules.value, "logging_enabled", true)
        }
      }
    }
  }


}
