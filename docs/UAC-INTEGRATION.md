# 传音用户中心 (UAC) 统一身份集成指南

Aegis 控制台通过可插拔认证提供者对接传音企业身份。当前支持：

| 提供者 | 配置值 | 适用 |
|--------|--------|------|
| `local` | 默认 | 独立部署、无 IdP |
| `oidc` | `AEGIS_AUTH_PROVIDER=oidc` | 标准 OIDC IdP（Keycloak/Casdoor/Authing/AzureAD/自建4A） |
| `uac` | `AEGIS_AUTH_PROVIDER=uac` | **传音用户中心 (UAC)** — 企业统一身份 |

---

## UAC 接入（传音企业身份）

### 前置准备（对接指南 §一）
1. 在传音开放平台创建应用，获取 **App ID** 和 **App Secret**。
2. 申请接口访问权限及数据范围权限（校验 Token、获取用户信息）。

### UAC 门户环境推导
UAT 环境 = 二级域名末尾加 `uat`：
- 生产门户: `https://pfuac.transsion.com/#/c-login`
- UAT 门户:  `https://pfuacuac.transsion.com/#/c-login` （内网/VPN 可达）
配置 `AEGIS_UAC_PORTAL` 指向对应环境门户。**UAT appId 必须配 UAT 门户**，否则门户报「APPID 无效」。

### 网关环境（对接指南 §一.1，务必用 `-intra-` 内网域名）
| 环境 | 网关 |
|------|------|
| DEV | https://dev-paas.transsion.com |
| TEST | https://test-paas.transsion.com |
| UAT | https://uat-intra-paas.transsion.com |
| PROD-深圳 | https://sz-intra-paas.transsion.com |
| PROD-香港 | https://hk-intra-paas.transsion.com |
| PROD-法兰克福 | https://fra-intra-paas.transsion.com |

### 配置（服务器 `/etc/aegis/console.env`）
```bash
AEGIS_AUTH_PROVIDER=uac
AEGIS_UAC_GATEWAY=https://sz-intra-paas.transsion.com   # 按部署地域选择
AEGIS_UAC_APP_ID=<开放平台 App ID>
AEGIS_UAC_APP_SECRET=<开放平台 App Secret>
AEGIS_UAC_PORTAL=https://pfuac.transsion.com/#/c-login   # 可选, 默认此值
AEGIS_SESSION_SECRET=<随机 64 位 hex>
```
然后 `sh scripts/deploy-console.sh`。登录页自动出现「传音统一身份登录」按钮。

### SSO 流程（对接指南 §二.1 登录门户）
```
1. 未登录用户访问控制台 → 登录页显示「传音统一身份登录」
2. 点击 → 重定向 UAC 门户:
   https://pfuac.transsion.com/#/c-login?appId=<APP_ID>&redirect=<控制台回调>
3. 用户在 UAC 完成登录
4. UAC 回跳 redirect 并追加 token / rtoken / employeeNo
5. 控制台回调 /api/auth/uac/callback:
   a. POST {gateway}/uac-auth-service/v2/api/uac-auth/rtoken/check   (校验 token)
      Header: P-Auth / P-Rtoken / P-AppId
   b. POST {gateway}/uac-auth-service/v2/api/uac-auth/utoken/getUserInfo (取用户)
      返回工号 / 邮箱 / 部门
   c. 签发 Aegis 会话 cookie (HMAC-SHA256, 7 天)
6. 用户进入控制台, 身份 = UAC 工号
```

### 核心 API 字典（对接指南 §四）
| 功能 | 方法 | 路径 |
|------|------|------|
| 重定向登录 | GET | /uac-auth-service/v2/api/uac-auth/login/redirect/web-login |
| API 登录 | POST | /uac-auth-service/v2/api/uac-auth/login/account |
| 获取 RSA 公钥 | GET | /uac-auth-service/v2/api/uac-auth/crypto/rsaKeyPair |
| 校验 Token | POST | /uac-auth-service/v2/api/uac-auth/rtoken/check |
| 获取 Token | POST | /uac-auth-service/v2/api/uac-auth/rtoken/get |
| 获取用户信息 | POST | /uac-auth-service/v2/api/uac-auth/utoken/getUserInfo |

受限接口 Header：`P-Auth`(请求令牌) + `P-Rtoken`(用户令牌) + `P-AppId`(应用ID)。

### 错误码（对接指南 §五）
| 码 | 含义 | 处理 |
|----|------|------|
| 10009 | 无效签名 | 检查签名算法 |
| 10013 | 无数据权限 | 开放平台申请接口/字段权限 |
| 30004 | 令牌为空 | Header 遗漏 P-Auth/P-Rtoken, 重新引导登录 |
| 30008 | 非法用户令牌 | Token 过期/登出, 重新登录 |
| 10306 | 登录密码错误 | API 登录模式密码解密失败 |

---

## 与 4A 的关系
UAC 解决**认证 (Authentication)**。授权/审计可叠加：
- 设备 owner 字段由 UAC `employeeNo` 自动填充（登录后 cookie `aegis_user`）
- 部门信息存 cookie `aegis_dept`，可用于风险工单通知路由
- 完整 4A (AuthZ/Accounting/Audit) 走 `aegis_4a_interface.py` 的 `FourAInterface`，UAC 作为其 Authentication 实现之一

## 回退
若 UAC 不可达，改 `AEGIS_AUTH_PROVIDER=local` 并重启即回本地密码登录，不影响已签发会话。


## 反向代理交付（标准 nginx）
生产反向代理标准交付为 **nginx**（非 Caddy）。配置见 `deploy/nginx/aegis.nginx.conf`：
- 443 TLS → wrangler console (127.0.0.1:8787)
- `/aegis/` → Collector (127.0.0.1:8931)，剥离前缀
- 80 → 301 https（未备案域名 80 端口可能被云厂商拦截，用户直接走 https）
- **必须** `proxy_set_header X-Forwarded-Proto https`：控制台 SSO redirect_uri 依赖它
  （TLS 在 nginx 终止，后端 worker 否则看到 http origin）
- 证书：Let's Encrypt，`/etc/nginx/ssl/tx.yjiod.com.{crt,key}`
  （可从 Caddy 存储复制过渡，或 certbot 申请/续期）
nginx<1.25.1 用 `listen 443 ssl http2;`；≥1.25.1 用 `http2 on;`。
