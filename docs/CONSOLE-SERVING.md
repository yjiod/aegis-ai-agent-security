# 控制台 Serving 生产化评估与设计（研究稿，迁移留有人窗口）

现状：控制台以 `wrangler dev --config /opt/aegis/console-server/wrangler.json` 常驻（self-hosted，
无 Cloudflare 远端）。`wrangler dev` 是**开发服务器**：启动时 esbuild 打包全部路由、带 inspector/
热更开销；3.7GB 小盒上冷启 1–4 分钟、峰值内存 ~1.3–1.5G，曾因此内存抖动→worker 不 bind→公网 502。

已做的零风险加固（已上线）：
- `NODE_ENV=production`（关 dev 重编译/热更开销）。
- drop-in `MemoryHigh=1600M / MemoryMax=2400M`（给冷启留余量，仍受 cgroup 约束）。
- 自愈看门狗 `aegis-console-healthcheck.timer`（60s 探活 + **600s boot grace + 3 次连续失败才重启**）。
  2026-09-25 生产事故教训：冷启 /login 编译实测可达 150–310s，旧版"10s 探测 + 240s grace"在服务满 4 分钟后，
  任何一次撞上冷编译窗口的探测超时都触发 restart → 新一轮冷编译 → 再超时，形成连环重启
  （当日 40 分钟内 4 次），用户请求撞上冷窗口即 nginx 60s → HTTP 504。
  新策略：探测 15s 超时、服务启动 600s 内失败不计数、连续 3 次失败（状态文件 /run/aegis-console-fail.count）
  才重启——冷编译慢与真死锁可区分。
- `ExecStartPost` 就绪轮询 + `TimeoutStartSec=360`（restart 阻塞到 worker 真可服务）。

## 候选方案

**A. 维持 wrangler dev + 现有加固（现状）**
- 优点：零迁移风险；assets(/downloads、_next static) 由 worker 一体服务，无配置分裂。
- 缺点：冷启重（每次重启重新打包）；dev 服务器语义不适合长期生产。
- 适用：当前规模（≤百台终端、低 QPS）可接受；配合看门狗+预热已把故障窗口压到分钟级。

**B. workerd 直跑 + [assets]**
- 用 `wrangler deploy --dry-run --outdir` 产出 worker bundle + workerd 配置，`workerd` 直跑（无 dev 开销）。
- 风险：workerd 的 [assets] 支持版本依赖、静态资源 MIME/cache 头需自行对齐；配置分裂后
  /downloads 大文件(.msi/.pkg 数十 MB)走 worker 资产仍占 worker 内存/连接。**不推荐**大文件走 worker。

**C. 静态/动态分离：nginx 直供静态 + worker 只服务 API/HTML（推荐）**
- 把 `dist/client`（_next static、/downloads 大文件）交给 nginx `alias` 直供（现网已有
  /downloads/ alias 到 /opt/aegis/native-dist 的先例），worker 只服务 HTML/API（无大资产）。
- 收益：worker  bundle/内存显著下降、冷启更快；大文件走 nginx  sendfile 不占 worker。
- 风险/工作：nginx location 需覆盖 _next static 的 immutable cache 头与 /downloads 的 no-store
  （安装包/清单不可缓存）；HTML 路由仍回 worker；需灰度切换+回滚预案。**中等风险→有人窗口做**。
- 回滚：nginx 配置回退 + worker 不变；或 unit 切回 wrangler dev。

**D. 部署到 Cloudflare Workers**：本产品 self-hosted（collector/PG 在内网），不适用。

## 迁移 checklist（有人窗口执行，方案 C）
1. 备份现网 nginx 配置 + unit；准备回滚命令。
2. nginx 增加 `location /_next/static/ { alias /opt/aegis/client/_next/static/; add_header Cache-Control "public, max-age=31536000, immutable"; }`
   与 `location /downloads/ { alias /opt/aegis/client/downloads/; add_header Cache-Control no-store; }`
   （保留既有 native-dist 的 /downloads/ 精确匹配优先）。
3. worker 侧确认 HTML/API 不依赖 worker 资产（vinext build 产物拆分验证）。
4. 灰度：先在一台终端/一个路径验证静态命中（curl -I 看 cache 头与命中 nginx），再全量。
5. 观察冷启时间/内存（systemctl show MemoryCurrent）、看门狗无误重启。
6. 回滚预案演练一次（nginx 回退 → 静态仍可达）。

## 结论
当前规模下方案 A+加固 已足够（故障窗口分钟级、有自愈）；方案 C 是下一步性能/稳定性收益最大项，
但属中等风险配置变更，**留有人窗口按 checklist 灰度执行**，不在无人值守时切换。
