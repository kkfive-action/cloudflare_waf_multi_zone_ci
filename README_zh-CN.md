[English](./README.md) | [繁體中文](./README_zh-TW.md) | 简体中文

# Cloudflare WAF 自动更新（Terraform + AbuseIPDB）

用 GitHub Actions 自动帮你的 Cloudflare zone 维护一组 WAF custom rules。
每天从 AbuseIPDB 抓坏 ASN 更新黑名单，顺便放行搜索引擎 / 监控这类正常服务。
多个 zone 可以一起管，规则写在一个 `rules.yaml` 里。

## 它怎么跑

GitHub Actions（每天 03:00 UTC + push main + 手动）会做这几步：

1. `update_abuseipdb_asns.py` → 更新 `rules.yaml` 的 ASN 清单，顺便查出每个 zone 现有的 ruleset id 写进 `import_targets.txt`
2. `terraform import` → 把现有 ruleset 拉进 state
3. `terraform apply` → **in-place 更新**，不会删掉重建，所以没有「中间一段没防护」的空窗

> 早期版本是「先 DELETE 整个 ruleset 再重建」，每天都有短暂空窗、还会把手动改的规则洗掉。现在改成 import → apply，干净很多。

## 怎么用

**1. Fork 这个 repo。**

**2. 设两个 GitHub Secret**（Settings → Secrets and variables → Actions）：

| Name | 要干嘛 |
|---|---|
| `CLOUDFLARE_API_TOKEN` | **Zone : WAF : Edit** 权限的 API Token。一把 token 只能管它所属账号的 zone，别放别账号的进来。Client IP filtering 留空，不然会挡到 runner。 |
| `ABUSEIPDB_API_KEY` | 可选。没设就用内建的静态 ASN 清单，功能照常。 |
| `SECRET_PATH_PREFIX` | `8cawecg8gu` 配置站的秘密路径前缀。路径不含它的请求直接 403。**值永远不要提交进仓库**——只存在这里。 |

**3. 改 `terraform.tfvars`**，填你自己的 zone（域名 = zone id，dashboard 该网域 Overview 右下角找得到）：

```hcl
zone_ids = {
  "yourdomain.com" = "你的zone_id"
}
```

**4. push 上去**，Actions 会自己跑。也可以去 Actions 页手动 dispatch。

## 改规则

全部在 `rules.yaml`，由上到下就是优先顺序。默认五条：

1. **Allow Trusted & Legitimate Traffic** — 合并 skip：自家基础设施 IP（账户级 list `$trusted_infrastructure`）+ 合法服务（搜索引擎 UA + ASN 双重验证：Googlebot 15169/396982、Bingbot 8075；社交预览 bot 按 UA）。**UA 单独不作为信任依据。** 免费账户只有 1 个 IP-only list 额度；如需监控专用域名（如 `status.example.com`），直接在这条规则的 expression 内联 `or (http.host eq "status.example.com")`（不占 list 额度）。该 list 是外部依赖（不受 Terraform 管理）——改名或删除会让 CI 的 apply 失败。
2. **Block Known Bad ASNs** — 坏 ASN 黑名单（expression 每次跑被脚本重写，手改没用）。
3. **Block Non-GET Methods on Secret Config Host** — 仅 `8cawecg8gu.kkfive.top`：非 GET/HEAD 方法 403；GET/HEAD 但路径不含秘密前缀也 403。秘密值来自 `SECRET_PATH_PREFIX` GitHub Secret（rules.yaml 里是占位符，CI 运行时注入）。
4. **Block Malicious Traffic & Exploit Probes** — 扫描/监控 UA、漏洞路径、死技术栈后缀（.php/.asp/.jsp 等）、危险 HTTP 方法、VCS 目录、Vite dev 指纹、框架调试端点、密钥文件、路径穿越编码。
5. **Challenge High Threat Score Traffic** — 高威胁分数丢 managed challenge（为 API 服务保留）。

`skip` 规则可以加 `skip_current_ruleset: true`（跳过后面所有 custom rules）跟 `products`（跳过哪些受管产品）。

> 小提醒：**别用「挑战所有海外流量」那种国家规则**。如果你的站是 SPA + API，managed challenge 会卡死前端的 XHR / preflight，海外用户直接进不来。用 `threat_score` 之类比较安全。

## 本机先看 plan（建议）

别让 CI 盲 apply 到正式站，先本机看一次 diff：

```bash
export TF_VAR_cloudflare_api_token="你的token"   # 只在你终端机，别贴出去
python update_abuseipdb_asns.py
terraform init
while IFS=$'\t' read -r a id; do terraform import "$a" "$id"; done < import_targets.txt
terraform plan    # 确认是 in-place、没有 destroy/recreate
```

plan 干净再 `terraform apply` 或 merge。

## 卡关时

- apply 403 `code 10000`：多半不是 token 坏，是 tfvars 里有 zone **不在这把 token 的账号**底下 → 拿掉那个 zone。
- token 到底活不活：`curl -s https://api.cloudflare.com/client/v4/user/tokens/verify -H "Authorization: Bearer $TF_VAR_cloudflare_api_token"`
- 正常服务被挡：不要加 UA 白名单（UA 可伪造）——把它的出口 IP 加进 `$trusted_infrastructure`，或在第一条规则内联专用域名。
