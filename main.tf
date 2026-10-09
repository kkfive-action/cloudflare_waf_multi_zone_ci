terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

locals {
  config = yamldecode(file("${path.module}/rules.yaml"))
}

# 每個 zone 一個 http_request_firewall_custom 階段的 entry point ruleset（kind = "zone"）。
# 規則內容來自 rules.yaml；獨立 ASN 規則的 expression 由 update_abuseipdb_asns.py 就地更新。
#
# v5 重點：rules 是 list attribute（不是 v4 的 dynamic block）；action_parameters / logging
# 是 object（= {...}）而非 block。skip 規則才帶 action_parameters，其餘設 null。
resource "cloudflare_ruleset" "waf_ruleset" {
  for_each    = var.zone_ids
  zone_id     = each.value
  name        = "Terraform Managed WAF Rules"
  description = "WAF rules auto-updated from AbuseIPDB"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    for idx, rule in local.config.rules : {
      ref         = format("rule_%02d", idx)
      description = rule.name
      expression  = rule.expression
      action      = rule.action
      enabled     = true

      # 只有 skip 規則需要 action_parameters：
      #   products             → 跳過的受管產品（waf / bic / rateLimit ...）
      #   skip_current_ruleset → true 時跳過本 ruleset 其餘 custom rules（ruleset = "current"）
      action_parameters = rule.action == "skip" ? {
        products = lookup(rule, "products", null)
        ruleset  = lookup(rule, "skip_current_ruleset", false) ? "current" : null
      } : null

      logging = rule.action == "skip" ? {
        enabled = lookup(rule, "logging_enabled", true)
      } : null
    }
  ]
}

# 每個 zone 一條 rate limit 規則（免費版每 zone 只有 1 條額度，獨立於 custom rules 的 5 條）。
# 兜底按 IP 計數：200 次/10 秒超出則 block 10 分鐘——正常人瀏覽 10 秒內 <50 次，
# SPA 首屏突發也碰不到；腳本/掃描器必撞。白名單不走這裡：rules.yaml 前兩條 skip 的
# products 已含 rateLimit，可信 IP 與合法 bot 天然豁免。
# 誤傷處理：企業 NAT 出口若被誤攔，先把 action 降為 managed_challenge 觀察。
resource "cloudflare_ruleset" "rate_limit" {
  for_each    = var.zone_ids
  zone_id     = each.value
  name        = "Rate Limiting"
  description = "Per-IP flood & brute-force cap"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [{
    ref         = "rule_00"
    description = "Block IPs exceeding 200 req/10s"
    # 全匹配：Rules 語言沒有裸 true 字面量，path 必以 / 開頭故恒真
    expression = "(http.request.uri.path contains \"/\")"
    action     = "block"
    enabled    = true

    ratelimit = {
      # cf.colo.id 必須顯式帶上：CF 計數在 colo 層面處理，僅 ip.src 會被 API
      # 拒絕（code 20155）；控制台的 "IP" 選項底層就是 ip.src + cf.colo.id
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = 10
      requests_per_period = 200
      mitigation_timeout  = 600
    }
  }]
}
