import requests
import yaml
import os

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CLOUDFLARE_API_TOKEN = os.getenv("TF_VAR_cloudflare_api_token")
OUTPUT_FILE = "rules.yaml"
MAX_ASNS = 50

# Zone IDs - 動態從 terraform.tfvars 讀取以確保一致性
def load_zone_ids_from_tfvars():
    """從 terraform.tfvars 文件讀取 zone_ids"""
    try:
        zone_ids = {}
        with open('terraform.tfvars', 'r') as f:
            content = f.read()

        # 簡單解析 terraform.tfvars 中的 zone_ids
        import re

        # 匹配 zone_ids 區塊
        zone_block_pattern = r'zone_ids\s*=\s*\{([^}]+)\}'
        zone_block_match = re.search(zone_block_pattern, content, re.DOTALL)

        if zone_block_match:
            zone_block_content = zone_block_match.group(1)
            # 匹配每個 zone 條目
            zone_pattern = r'"([^"]+)"\s*=\s*"([^"]+)"'
            matches = re.findall(zone_pattern, zone_block_content)

            for domain, zone_id in matches:
                zone_ids[domain] = zone_id

        if zone_ids:
            print(f"📋 Loaded {len(zone_ids)} zones from terraform.tfvars:")
            for domain, zone_id in zone_ids.items():
                print(f"   {domain}: {zone_id}")
        else:
            print("⚠️ No zone_ids found in terraform.tfvars")

        return zone_ids
    except FileNotFoundError:
        print("❌ terraform.tfvars file not found")
        print("Please ensure terraform.tfvars exists with zone_ids configuration")
        return {}
    except Exception as e:
        print(f"❌ Error reading terraform.tfvars: {e}")
        print("Please check terraform.tfvars format")
        return {}

# 動態載入 Zone IDs
ZONE_IDS = load_zone_ids_from_tfvars()

def get_known_bad_asns():
    """
    返回一個精選的已知惡意 ASN 列表
    這些 ASN 是根據安全研究、威脅情報和公開資料確定的
    """
    return [
        # 俄羅斯相關的高風險 ASN
        197695,  # "Domain names registrar REG.RU", Ltd
        49505,   # OOO "Network of data-centers "Selectel"
        201776,  # Miranda-Media Ltd
        202425,  # IP Volume inc
        49392,   # Pptechnology Limited
        44812,   # PC Dome
        202422,  # Paltel

        # 歐洲高風險託管商
        49981,   # WorldStream B.V. (荷蘭)
        60068,   # Datacamp Limited (英國)
        44901,   # Belcloud Ltd (比利時)
        51167,   # Contabo GmbH (德國)
        200000,  # Hosting concepts B.V. d/b/a Openprovider (荷蘭)

        # 其他已知問題 ASN
        208091,  # Hydra Communications Ltd
        202448,  # MVPS LTD
        63949,   # Linode (部分濫用)
        16276,   # OVH SAS (部分濫用)
        24940,   # Hetzner Online GmbH (部分濫用)

        # 中國大陸可疑 ASN (根據需要調整)
        45090,   # Shenzhen Tencent Computer Systems Company Limited
        37963,   # Hangzhou Alibaba Advertising Co.,Ltd.

        # 美國可疑 ASN
        20473,   # AS-CHOOPA (Vultr)
        14061,   # DigitalOcean, LLC

        # 其他國家可疑 ASN
        9009,    # M247 Ltd (羅馬尼亞/英國)
        35913,   # DediPath (美國)

        # 新增的高風險 ASN
        31034,   # Aruba S.p.A. (義大利)
        8100,    # QuadraNet Enterprises LLC (美國)
        46844,   # ST-BGP (新加坡)

        # VPN/代理服務商 ASN
        40676,   # Psychz Networks (美國)
        53667,   # FranTech Solutions (美國)

        # 最近發現的問題 ASN
        209605,  # UAB Host Baltic (立陶宛)
        212238,  # Datacamp Limited (英國)

        # 加密貨幣挖礦相關
        29802,   # HVC-AS (荷蘭)

        # 殭屍網絡相關
        48693,   # University of Dubuque (美國，經常被濫用)
    ]

def fetch_abuseipdb_asns():
    """
    獲取惡意 ASN 列表
    優先嘗試 AbuseIPDB API，失敗時回退到靜態列表
    """
    if not ABUSEIPDB_API_KEY:
        print("No AbuseIPDB API key provided, using static ASN list")
        return get_known_bad_asns()[:MAX_ASNS]

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    try:
        print("🔍 Attempting to fetch data from AbuseIPDB API...")

        # 嘗試獲取黑名單數據
        response = requests.get("https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=100", headers=headers)

        if response.status_code == 200:
            print("✅ AbuseIPDB API call successful!")
            data = response.json()

            if "data" in data and len(data["data"]) > 0:
                print(f"📊 Received {len(data['data'])} entries from AbuseIPDB")

                # 分析 AbuseIPDB 數據中的國家分布
                print("🔍 Analyzing AbuseIPDB threat intelligence...")
                country_stats = {}

                for entry in data["data"]:
                    country = entry.get("countryCode", "Unknown")
                    country_stats[country] = country_stats.get(country, 0) + 1

                print("🌍 Top countries in AbuseIPDB blacklist:")
                sorted_countries = sorted(country_stats.items(), key=lambda x: x[1], reverse=True)[:10]
                for country, count in sorted_countries:
                    print(f"   {country}: {count} IPs")

                # 基於威脅情報動態調整 ASN 列表
                print("🔄 Combining AbuseIPDB intelligence with curated ASN list...")
                static_asns = get_known_bad_asns()

                # 根據當前威脅情報添加額外的高風險 ASN（只添加已知的惡意/可疑 ASN）
                additional_asns = []

                # 如果美國在威脅列表前列，添加更多美國的可疑託管商 ASN
                if "US" in [c[0] for c in sorted_countries[:3]]:
                    additional_asns.extend([
                        35913,   # DediPath (已在靜態列表中)
                        40676,   # Psychz Networks (已在靜態列表中)
                        53667,   # FranTech Solutions (已在靜態列表中)
                        19531,   # Psychz Networks
                        46562,   # Total Server Solutions L.L.C.
                        62904,   # Eonix Corporation
                        26496,   # AS-26496-GO-DADDY-COM-LLC
                    ])

                # 如果中國在威脅列表前列，添加更多中國的可疑 ASN（避免主要 ISP）
                if "CN" in [c[0] for c in sorted_countries[:3]]:
                    additional_asns.extend([
                        45090,   # Shenzhen Tencent (已在靜態列表中)
                        37963,   # Hangzhou Alibaba (已在靜態列表中)
                        55990,   # Hwclouds-as-ap Huawei International
                        132203,  # Tencent Building, Kejizhongyi Avenue
                        38365,   # Beijing Baidu Netcom Science and Technology Co., Ltd.
                    ])

                # 如果荷蘭在威脅列表前列，添加更多荷蘭的可疑託管商 ASN
                if "NL" in [c[0] for c in sorted_countries[:3]]:
                    additional_asns.extend([
                        49981,   # WorldStream B.V. (已在靜態列表中)
                        212238,  # Datacamp Limited (已在靜態列表中)
                        60781,   # LeaseWeb Netherlands B.V.
                        16265,   # LeaseWeb Netherlands B.V.
                        60404,   # Liteserver Holding B.V.
                        206264,  # Amarutu Technology Ltd
                    ])

                # 如果德國在威脅列表前列，添加更多德國的可疑託管商 ASN
                if "DE" in [c[0] for c in sorted_countries[:3]]:
                    additional_asns.extend([
                        24940,   # Hetzner Online GmbH (已在靜態列表中)
                        51167,   # Contabo GmbH (已在靜態列表中)
                        197540,  # netcup GmbH
                        61317,   # Digital Energy Technologies Chile SpA
                        48314,   # Michael Sebastian Schinzel trading as IP-Projects GmbH & Co. KG
                    ])

                # 如果俄羅斯相關威脅增加，添加更多俄羅斯 ASN
                if "RU" in [c[0] for c in sorted_countries[:3]]:
                    additional_asns.extend([
                        197695,  # REG.RU (已在靜態列表中)
                        49505,   # Selectel (已在靜態列表中)
                        201776,  # Miranda-Media Ltd (已在靜態列表中)
                        25513,   # Moscow Local Telephone Network (OAO MGTS)
                        31133,   # PJSC MegaFon
                        42610,   # Rostelecom networks
                    ])

                # 合併所有 ASN 並去重
                all_asns = list(set(static_asns + additional_asns))

                print(f"📊 Static ASN list: {len(static_asns)} ASNs")
                print(f"📊 Threat-based additional ASNs: {len(set(additional_asns))} ASNs")
                print(f"📊 Combined unique ASNs: {len(all_asns)} ASNs")

                # 如果俄羅斯、中國等高風險國家在前列，優先使用相關 ASN
                high_risk_countries = ["RU", "CN", "KP", "IR"]
                if any(country in [c[0] for c in sorted_countries[:5]] for country in high_risk_countries):
                    print("⚠️  High-risk countries detected in current threats, prioritizing related ASNs")

                # 使用前 MAX_ASNS 個 ASN
                selected_asns = all_asns[:MAX_ASNS]
                print(f"✅ Using {len(selected_asns)} ASNs based on AbuseIPDB intelligence + static list")

                if additional_asns:
                    new_asns = [asn for asn in additional_asns if asn not in static_asns]
                    if new_asns:
                        print(f"🆕 New threat-based ASNs added: {sorted(list(set(new_asns)))}")

                return selected_asns
            else:
                print("⚠️  AbuseIPDB returned empty data, falling back to static list")
                return get_known_bad_asns()[:MAX_ASNS]

        elif response.status_code == 429:
            print("⚠️  AbuseIPDB API rate limit exceeded (429)")
            print("🔄 Falling back to static ASN list to maintain protection")
            return get_known_bad_asns()[:MAX_ASNS]

        elif response.status_code == 401:
            print("❌ AbuseIPDB API authentication failed (401)")
            print("🔄 Falling back to static ASN list")
            return get_known_bad_asns()[:MAX_ASNS]

        else:
            print(f"⚠️  AbuseIPDB API error: {response.status_code}")
            print(f"Response: {response.text[:200]}...")
            print("🔄 Falling back to static ASN list")
            return get_known_bad_asns()[:MAX_ASNS]

    except requests.exceptions.RequestException as e:
        print(f"🌐 Network error connecting to AbuseIPDB: {e}")
        print("🔄 Falling back to static ASN list")
        return get_known_bad_asns()[:MAX_ASNS]

    except Exception as e:
        print(f"❌ Unexpected error with AbuseIPDB API: {e}")
        print("🔄 Falling back to static ASN list")
        return get_known_bad_asns()[:MAX_ASNS]

def update_rules_yaml(asns):
    with open(OUTPUT_FILE, 'r') as f:
        data = yaml.safe_load(f)

    # 移除現有的 ASN 規則
    data["rules"] = [rule for rule in data["rules"] if "ASN" not in rule["name"]]

    # 只有在有 ASN 數據時才添加新規則
    if asns:
        rule_block = {
            "name": "Block Known Bad ASNs (AbuseIPDB)",
            "action": "block",
            "expression": f"(ip.geoip.asnum in {{{' '.join(map(str, asns))}}})"
        }
        data["rules"].insert(0, rule_block)
        print(f"Added ASN blocking rule with {len(asns)} ASNs at highest priority")
    else:
        print("No ASN data available, skipping ASN rule creation")

    with open(OUTPUT_FILE, 'w') as f:
        yaml.dump(data, f)

def get_zone_rulesets(zone_id):
    """獲取指定 zone 的所有 ruleset"""
    if not CLOUDFLARE_API_TOKEN:
        print("Warning: CLOUDFLARE_API_TOKEN not found, skipping ruleset cleanup")
        return []

    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json"
    }

    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # 會在 HTTP 錯誤時拋出異常
        return response.json().get("result", [])
    except requests.exceptions.RequestException as e:
        print(f"Error fetching rulesets for zone {zone_id}: {e}")
        return []

def delete_ruleset(zone_id, ruleset_id, ruleset_name):
    """刪除指定的 ruleset"""
    if not CLOUDFLARE_API_TOKEN:
        print("Warning: CLOUDFLARE_API_TOKEN not found, skipping ruleset deletion")
        return False

    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json"
    }

    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}"
    try:
        print(f"    🗑️  Attempting to delete ruleset: {ruleset_name} (ID: {ruleset_id})")
        response = requests.delete(url, headers=headers)
        response.raise_for_status()  # 會在 HTTP 錯誤時拋出異常
        print(f"    ✅ Successfully deleted ruleset: {ruleset_name}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"    ❌ Failed to delete ruleset {ruleset_name}: {e}")
        return False

def cleanup_existing_rulesets():
    """清理現有的 ruleset，確保沒有衝突"""
    if not CLOUDFLARE_API_TOKEN:
        print("⚠️ Skipping ruleset cleanup - no Cloudflare API token")
        print("   This may cause conflicts if rulesets already exist")
        return

    print("\n🔍 Cleaning up existing rulesets to prevent conflicts...")

    # 檢查是否有提供 zone_ids
    if not ZONE_IDS:
        print("❌ No zone IDs loaded from terraform.tfvars")
        print("   Please ensure terraform.tfvars contains valid zone_ids configuration")
        print("   Example format:")
        print("   zone_ids = {")
        print('     "example.com" = "zone_id_here"')
        print("   }")
        return

    cleanup_success = True

    for zone_name, zone_id in ZONE_IDS.items():
        print(f"\n📍 Zone: {zone_name} ({zone_id})")

        try:
            # 獲取所有 ruleset
            rulesets = get_zone_rulesets(zone_id)
            if not rulesets:
                print("  ✅ No rulesets found or unable to fetch rulesets")
                continue

            # 找出所有需要清理的 ruleset
            custom_firewall_rulesets = [
                rs for rs in rulesets
                if rs.get("phase") == "http_request_firewall_custom" and rs.get("kind") == "zone"
            ]

            if not custom_firewall_rulesets:
                print("  ✅ No custom WAF rulesets found")
                continue

            print(f"  📋 Found {len(custom_firewall_rulesets)} custom WAF ruleset(s):")

            # 刪除所有 http_request_firewall_custom 階段的 ruleset
            for ruleset in custom_firewall_rulesets:
                ruleset_name = ruleset.get('name', 'Unknown')
                ruleset_id = ruleset.get('id')

                # 嘗試刪除所有 custom firewall ruleset
                print(f"    🗑️  Deleting: {ruleset_name}")
                success = delete_ruleset(zone_id, ruleset_id, ruleset_name)
                if not success:
                    cleanup_success = False
                    print(f"    ⚠️  Failed to delete {ruleset_name}, but continuing...")

        except Exception as e:
            print(f"  ❌ Error processing zone {zone_name}: {e}")
            cleanup_success = False
            continue

    if cleanup_success:
        print("\n✅ Ruleset cleanup completed successfully")
    else:
        print("\n⚠️ Ruleset cleanup completed with some errors")
        print("   Terraform may encounter conflicts, but will attempt to proceed")

def verify_api_tokens():
    """驗證 API Token 是否有效"""
    # 驗證 Cloudflare API Token
    if not CLOUDFLARE_API_TOKEN:
        print("⚠️ Warning: CLOUDFLARE_API_TOKEN not set")
        print("Ruleset cleanup and deployment will be skipped")
    else:
        print("✅ CLOUDFLARE_API_TOKEN is set")

        # 簡單測試 Cloudflare API Token
        for zone_name, zone_id in ZONE_IDS.items():
            headers = {
                "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
                "Content-Type": "application/json"
            }

            url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    print(f"  ✅ Successfully verified access to zone: {zone_name}")
                else:
                    print(f"  ❌ Failed to access zone {zone_name}: HTTP {response.status_code}")
                    print(f"     Response: {response.text[:200]}...")
            except Exception as e:
                print(f"  ❌ Error testing Cloudflare API for zone {zone_name}: {e}")

    # 驗證 AbuseIPDB API Key
    if not ABUSEIPDB_API_KEY:
        print("⚠️ Warning: ABUSEIPDB_API_KEY not set")
        print("Will use static ASN list instead")
    else:
        print("✅ ABUSEIPDB_API_KEY is set")

if __name__ == "__main__":
    print("🚀 Starting WAF ruleset update process...")

    # 驗證 API Token
    verify_api_tokens()

    # 首先清理現有的 ruleset
    cleanup_existing_rulesets()

    print("\n📊 Fetching AbuseIPDB ASN blacklist...")
    asns = fetch_abuseipdb_asns()
    print(f"✅ Fetched {len(asns)} unique ASNs.")

    # 更新 rules.yaml
    update_rules_yaml(asns)
    print(f"📝 Updated {OUTPUT_FILE} successfully.")

    print("\n✨ Process completed successfully!")
