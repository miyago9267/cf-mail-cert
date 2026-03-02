# cf-mail-cert

Multi-zone Cloudflare ACME certificate manager for docker-mailserver.

自動為 docker-mailserver 申請和續期 TLS 憑證，支援跨不同 Cloudflare 帳號/zone 的多域名 SAN 憑證。

## 為什麼需要這個工具

- Kubernetes 有 cert-manager，但普通 Docker 環境沒有好的自動憑證管理方案
- 多人共用 mail server 時，域名分散在不同 Cloudflare 帳號下
- 需要一張 SAN 憑證涵蓋所有域名，並自動續期

## 架構

```tree
┌─────────────┐     ┌──────────────────┐     ┌───────────────┐
│  Scheduler  │────▶│  Cert Manager    │────▶│  ACME Server  │
│  (定時檢查)  │     │  (lego library)  │     │ (Let's Encrypt)│
└──────┬──────┘     └───────┬──────────┘     └───────────────┘
       │                    │
       │                    ▼
       │            ┌──────────────────┐
       │            │ MultiCloudflare  │──── Cloudflare API (account A)
       │            │   DNS Provider   │──── Cloudflare API (account B)
       │            └──────────────────┘
       ▼
┌─────────────┐     ┌──────────────────┐
│  Deployer   │────▶│  Docker Restart  │ or Hook Script
│ (atomic write)    │  (via socket)    │
└─────────────┘     └──────────────────┘
```

### 套件結構

```tree
cf-mail-cert/
├── cmd/main.go                        # CLI 入口 (issue/renew/serve)
├── internal/
│   ├── config/config.go               # YAML 設定檔解析與驗證
│   ├── dns/multi_cloudflare.go        # 多帳號 Cloudflare DNS-01 provider
│   ├── cert/manager.go                # ACME 憑證生命週期管理
│   ├── deploy/
│   │   ├── deployer.go                # 憑證部署 (atomic write) + reload 調度
│   │   ├── docker.go                  # Docker API container restart
│   │   └── hook.go                    # 自訂 shell hook 執行
│   └── scheduler/scheduler.go         # 定時續期排程器
├── config.example.yaml                # 設定檔範例
├── Dockerfile                         # Multi-stage Docker build
└── docker-compose.example.yaml        # 搭配 docker-mailserver 的範例
```

## 核心設計

### Multi-Account DNS Provider

`internal/dns/multi_cloudflare.go` 是本工具最核心的元件。

- 實作 lego 的 `challenge.Provider` 介面（`Present` / `CleanUp` / `Timeout`）
- 啟動時查詢每個 API token 能存取的 zones，建立 `domain → account` 路由表
- DNS-01 challenge 時自動找到正確的帳號和 zone 來建立 `_acme-challenge` TXT record
- Thread-safe：lego 可能並行處理多個域名的 challenge

### Cloudflare API Token 兩種模式

1. **單一 token** — 如果你被加為對方帳號的 member，一個 token 可以存取所有 zone
2. **多組 token** — 每個帳號各自產生 token，工具自動路由到正確的 token

### 憑證生命週期

`internal/cert/manager.go` 處理：

- ACME 帳號建立與持久化（ECDSA P-256 key）
- 憑證申請（所有域名合為一張 SAN 憑證）
- 到期前自動續期（預設 30 天前）
- 偵測域名清單變更時自動重新申請

### 部署與重載

`internal/deploy/` 處理：

- Atomic write（先寫 temp file 再 rename，避免 mailserver 讀到半寫的檔案）
- Docker API restart（透過掛載的 Docker socket）
- 或執行自訂 hook script

## 快速開始

### 1. 建立設定檔

```bash
cp config.example.yaml config.yaml
# 編輯 config.yaml，填入你的資訊
```

關鍵設定：

```yaml
acme:
  email: admin@example.com
  # 測試時先用 staging，確認沒問題再換 production
  ca_url: https://acme-staging-v02.api.letsencrypt.org/directory

cloudflare:
  # 方式一：單一 token
  api_token: "your-token"

  # 方式二：多組 token
  # accounts:
  #   - name: my-account
  #     api_token: "token-a"
  #   - name: friend-account
  #     api_token: "token-b"

domains:
  - mail.example.com
  - mail.friend.org

deploy:
  cert_path: /etc/dms/custom-certs/fullchain.pem
  key_path: /etc/dms/custom-certs/privkey.pem
  reload:
    method: docker
    docker:
      container_name: mailserver
```

### 2. Cloudflare API Token 權限

每個 token 需要：

- **Zone / Zone / Read** — 列出帳號下的 zones
- **Zone / DNS / Edit** — 建立和刪除 TXT records

### 3. 用 Docker Compose 部署

```bash
cp docker-compose.example.yaml docker-compose.yaml
# 編輯後啟動
docker compose up -d
```

### 4. 手動指令

```bash
# 強制申請新憑證
cf-mail-cert issue -config config.yaml

# 檢查並按需續期
cf-mail-cert renew -config config.yaml

# Daemon 模式（容器預設行為）
cf-mail-cert serve -config config.yaml
```

## 環境變數覆寫

敏感資訊可以用環境變數而非寫在設定檔：

| 環境變數 | 用途 |
| `CF_API_TOKEN` | 單一 token 模式的 API token |
| `CF_ACCOUNT_<NAME>_TOKEN` | 多組 token 模式，`<NAME>` 為帳號名稱的大寫（`-` 轉 `_`） |

例如帳號名稱為 `my-account`，對應 `CF_ACCOUNT_MY_ACCOUNT_TOKEN`。

## 依賴

| 套件 | 用途 |
| `github.com/go-acme/lego/v4` | ACME 協議客戶端 |
| `github.com/cloudflare/cloudflare-go` | Cloudflare API 客戶端 |
| `github.com/docker/docker` | Docker Engine SDK |
| `gopkg.in/yaml.v3` | YAML 設定檔解析 |

## 待辦 / 未來可能的改進

- [ ] 單元測試（mock Cloudflare API 和 lego client）
- [ ] 整合測試（使用 Let's Encrypt staging）
- [ ] 支援 webhook 通知（Slack/Discord/Email）憑證更新結果
- [ ] 支援多張憑證（不同 mail server 各自一張）
- [ ] Prometheus metrics endpoint
- [ ] 支援 ACME DNS alias mode（CNAME delegation）
