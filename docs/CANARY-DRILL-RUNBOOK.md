# Canary 灰度发布 + Enforce 演练 Runbook（SOP）

把「灰度发布 → 演练验证 → 观察 → 逐步放量 / 回滚」串成一条标准操作流程。两个可执行支点：

- **发布/推进/回滚侧**：`scripts/run_canary_release.py`（`--status` / `--rollout N` / `--advance` / `--rollback`，带推进门禁）
- **演练侧**：`scripts/run_enforce_drill.py`（deny→quarantine→回执→un-deny→auto-restore→回执，自动清理）

观察面：控制台「分发中心 → 自更新灰度(canary)」面板（放量徽标 / 逐设备桶号与在放量内 / 可封禁资产 / 已自更 N 台 / 自更异常 N 台 / 待发布提示）、「设备与 Agent」页舰队健康横幅（离线 / 版本漂移 / 自更异常）、审计日志（`policy:publish`、`policy:modules`、`settings:rollout`、`audit:export`）。

---

## 0. 前提与安全边界（每次必读）

- 目标环境：生产控制台 + Collector 健康；控制台自愈看门狗 active（`aegis-console-healthcheck.timer`）。
- **演练端点必须是非豁免(non-exempt)在线设备**（如隔离的测试 VM）。`run_enforce_drill.py` 会校验目标 `exempt=false` 否则中止。
- **开发主机永远豁免**：团队开发机应登记在 `enforce_exempt`（只报告不拦截）；不想让某台自动更新请把它加进 `pinned`（设备页或 `/api/settings/pinned`）。注意 exempt ≠ pinned：exempt 设备仍会自更，只有 pinned 才阻止自更（终端的自更逻辑只读 `agent_self_update.pinned`，不读 `enforce_exempt`）。
- 爆炸半径双闸（控制台发布闸 + 终端侧闸）：单发布影响资产 ≤5 且单设备占比 ≤10% 才可直接发布；超出需 typed override `I-ACCEPT-BLAST-RADIUS`；**绝对上限 20 资产 / 50% 不可 override**（必须拆批）。演练脚本用「1 夹具 + N filler」让 deny 占比天然 ≤10%。
- 凭据/真实地址只经环境变量或命令行传入（`AEGIS_CONSOLE`、`AEGIS_DRILL_USER`、`AEGIS_DRILL_PASSWORD`）；仓库脚本只留占位。演练账号勿启用 MFA（脚本不支持两步）。

## 1. 阶段 0 — 准备与基线确认

1. 控制台健康：`curl https://<console>/login` 应 200；Collector `/health` 200；看门狗 `systemctl is-active aegis-console-healthcheck.timer` = active。
2. 舰队基线：`python3 scripts/run_canary_release.py --status`。核对：
   - 当前 `rollout_percent`、`channel`、`enabled`；
   - 逐设备 `in_canary / agent_version / exempt / pinned / skills / self_update`；
   - `GATE: OK`（无坏自更回执）。若 `GATE: BLOCKED` 先走阶段 5 排查/回滚，不要继续。
3. 确认演练端点在线且 non-exempt、其 agent 版本与上报正常（`--status` 输出可见）。
4. 记录起点：导出审计基线（控制台审计页「导出 JSON」）留档。

## 2. 阶段 1 — 小比例灰度发布

```
python3 scripts/run_canary_release.py --rollout 10 --publish
```

- 保存放量比例并发布策略，使 `agent_self_update.rollout_percent` 生效。
- 核对输出 `published vN agent_self_update={...rollout_percent:10...}`。
- 控制台 canary 面板应显示「放量 10%」+ 对应桶号设备「在放量内」；面板若提示「待发布」说明设置未发布（本命令带 `--publish` 已发布）。
- 等待 ≥1 个扫描周期（终端自更发生在扫描周期内），再进入阶段 2/3。

## 3. 阶段 2 — Enforce 演练（验证封禁/恢复闭环）

```
python3 scripts/run_enforce_drill.py \
  --console https://<console> \
  --exec '<guest 命令运行器，如 prlctl exec "Windows 11" powershell -NoProfile -Command>' \
  --guest-home 'C:\Users\<测试端点用户>' --service AegisAgent --fillers 10
```

- 脚本自动：放夹具+filler → 发布 scoped deny+`skill_enforce=true` → 验证 quarantine 回执+磁盘 manifest → un-deny 发布 → 验证 auto-restore 回执+夹具回位 → 清理（基线策略+删夹具）。
- **通过标准**：末行 `DRILL PASSED: deny->quarantine->receipt and un-deny->auto-restore->receipt verified on <device>`。
- **失败处理**：任一环节 FAIL → 停止放量（阶段 5），脚本已尽力清理；若清理也失败（如控制台瞬态），手动重置基线：`skill_enforce=false`、清 deny、发布基线（见阶段 5）。
- 演练只触碰脚本自建的夹具名（随机后缀），对其它资产零影响；绝不选 exempt 设备。

## 4. 阶段 3 — 观察 canary（放量期间的持续门禁）

每次放量后、以及放量期间定期执行：

```
python3 scripts/run_canary_release.py --status
```

- 关注：`self-updated ok` 数量随放量上升；`bad self-update` 恒为 0；canary 面板「自更异常 N 台」为 0；舰队健康横幅无新增「自更异常 / 版本漂移」告警。
- 终端侧坏更新（preflight 拒绝 / 自动回滚 / 应用失败）会上报 `self_update` 并体现在 `--status` 与 canary 面板；这是"坏更新被终端自行拦截"的可观测闭环。
- 需要留证时：控制台审计页导出 JSON，或对单设备出证据包（审计页「导出证据包」，含 enforcement 回执与 self_update）。

## 5. 阶段 4 — 逐步放量 / 或回滚

**放量（每步之间等待 ≥1 扫描周期并重跑阶段 3 门禁）：**

```
python3 scripts/run_canary_release.py --advance --step 25 --publish   # 10→35→60→85→100
```

- `--advance` 内置门禁：存在任何坏自更回执即拒绝推进（退出码 2）。
- 到 100% 即全量；此后新设备/重装设备按 manifest 正常自更。

**回滚（任一门禁失败 / 发现坏更新）：**

```
python3 scripts/run_canary_release.py --rollback     # rollout=0 冻结自更通道
```

- 冻结只阻止**后续**自更；已更新设备不回退二进制（二进制自更本身有 preflight+sha 校验+`.prev` 自动回滚兜底）。
- 若问题出在 **enforce 封禁**（误封真实资产）：un-deny 该资产（处置中心改 monitor/allow）并发布；终端下个周期自动 restore（回执 `restored/policy_no_longer_denies`）；或直接把 `skill_enforce`/`mcp_enforce` 关回 false 并发布（全局停封禁）。
- 若问题出在**策略本身**：用控制台策略页回滚到上一发布版本（`/api/policy/rollback`），或重发一个修正策略。
- 回滚后重跑 `--status` 确认 `GATE` 与队列状态符合预期，并导出审计留档。

## 6. 阶段 5 — 收尾与留证

1. 全量后（或回滚稳定后）再跑一次 `--status` 存档截图/输出。
2. 导出该发布窗口的审计 JSON（含 `policy:publish` / `settings:rollout` / `policy:modules` 记录）。
3. 如演练过：确认演练夹具已清理、基线策略（`deny=[]`、`skill_enforce=false`）已发布（`run_enforce_drill.py` 清理步骤已做；`--status` 复核）。
4. 在发布记录/变更单中登记：发布版本号、rollout 轨迹（10→…→100 或回滚点）、演练结果（PASSED/FAIL+原因）、回滚点（如有）。

---

## 命令速查

| 目的 | 命令 |
|---|---|
| 看 canary 现状+门禁 | `run_canary_release.py --status` |
| 小比例发布 | `run_canary_release.py --rollout 10 --publish` |
| 推进一档 | `run_canary_release.py --advance --step 25 --publish` |
| 冻结自更(回滚通道) | `run_canary_release.py --rollback` |
| enforce 闭环演练 | `run_enforce_drill.py --exec <runner> --guest-home <home> --service AegisAgent` |
| 控制台观察 | 分发中心→canary 面板；设备页健康横幅；审计页导出 |

## 故障排查

- **控制台 502/000**：小盒冷启 1–4 分钟（`/login` 冷编译实测 150–310s）；轮询 `curl 127.0.0.1:8787/login` 至 200/307。看门狗为 **3-strike 策略：探测超时 15s、服务启动 600s 内的失败不计数（冷编译宽限）、连续 3 次失败才重启**（状态文件 `/run/aegis-console-fail.count`，unit 见 `ops/aegis-console-healthcheck.service`，事故背景见 [`CONSOLE-SERVING.md`](CONSOLE-SERVING.md)）。因此**冷启窗口内的探测失败不会触发重启**；勿把正常冷启当故障反复手动重启。nginx 读超时已放宽到 360s。
  > 旧版参数为"10s 探测 + 240s grace"，会在服务满 4 分钟后撞冷窗口即重启，形成连环重启并导致用户请求 504（2026-09-25 生产事故，40 分钟内 4 次）。若你在排查时看到 240s 这个数值，说明 unit 是旧版，需按 `ops/` 更新。
- **演练超时/瞬态**：脚本已带 API 重试与轮询容错；仍失败看 `--status` 与终端 `install.log`/服务日志。
- **设备不在线**：`--status` 里该设备 `last_seen` 旧；先恢复端点再演练/放量。
- **privacy/CI**：仓库脚本只留占位（console 域名、guest home）；改 `public/downloads/DEPLOYMENT-GUIDE.md`（在 release bundle 内）后必须重跑 `aegis_release_build.py` 重生 bundle，否则 CI verify 报 `bundle_content_mismatch`。

## 周期条件演练（OPT-IN，默认不启用）

把演练做成定时任务会让"封禁/恢复闭环"持续被验证，但它会**自动发布 scoped deny→un-deny 策略**并在目标
guest 上放/删夹具，属会改动生产策略的自动化，故**默认不安装**，由 owner 显式启用：

1. 复制模板并填占位：`scripts/com.aegis.enforce-drill.plist.example` →
   `~/Library/LaunchAgents/com.aegis.enforce-drill.plist`（`__REPO__/__CONSOLE__/__EXEC__/__GUEST_HOME__/__EXPECT_DEVICE__`）。
2. 凭据经 EnvironmentVariables 或 wrapper 从 keychain 读 `AEGIS_DRILL_USER/AEGIS_DRILL_PASSWORD`，勿明文入 plist。
3. `launchctl load …` 启用；`launchctl unload …` 停用。日志 `/tmp/aegis-enforce-drill.log`。

**条件守卫**：`--expect-device <id>` 使脚本先查该设备在线与否；不在线则跳过本次（exit 0），
不对离线端点空跑、不产生误告警/误发布。每 6 小时一次（StartInterval 21600）。

**启用前检查**：目标端点为非豁免测试机；其 agent 版本支持自更回执；告警推送已配置（否则演练失败无人知）。
演练失败（DRILL FAILED）时应停止放量（`run_canary_release.py --rollback`）并排查，勿继续推进。
