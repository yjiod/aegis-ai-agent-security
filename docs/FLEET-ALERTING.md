# 舰队告警推送（Fleet Alerting）

把"必须打开控制台才能发现"变成"主动推送到人"。独立轻量评估器 `scripts/aegis_alert_check.py`
由 systemd timer 周期运行：拉 collector `/v1/devices`，评估告警、去重节流、推 webhook。
不改任何治理状态（只读 collector + 出站 webhook）。

## 告警条件

| 类型 | 条件 | 严重度 |
|---|---|---|
| `device_offline` | `last_seen` 超过 `--offline-hours`（默认 2h）且曾在线（`last_seen>0`；从未上报的新注册设备不误报） | high |
| `self_update_failed` | 终端上报坏自更回执：`preflight_failed` / `rolled_back:*` / `apply_failed:*` | high |
| `critical_findings` | 设备 `latest_severity.critical > 0` | critical |

## 去重与节流

- 去重键 = `类型:device_id:detail首词`；状态存 `--state`（默认 `/var/lib/aegis/alert-state.json`，不可写回落 /tmp）。
- `--min-interval-hours`（默认 6h）内同类告警不重发；**发送成功才写状态**，发送失败下次重试。
- 未配置 webhook 或 `--dry-run`：只打印将推送的告警，不发送、不写状态（安全默认）。

## Webhook 格式

- `generic`（默认）：`POST {schema:"aegis.alert/v1", at, alerts:[{type,device_id,hostname,severity,detail}]}`
- `dingtalk`：`POST {msgtype:"text", text:{content:"Aegis 告警\n- [severity] type hostname: detail ..."}}`（钉钉机器人 webhook）

## 部署（systemd timer）

```
# /etc/systemd/system/aegis-alert.service
[Unit]
Description=Aegis fleet alert evaluator
After=aegis-collector.service
[Service]
Type=oneshot
EnvironmentFile=/etc/aegis/collector.env
ExecStart=/usr/bin/python3 /opt/aegis/aegis_alert_check.py --state /var/lib/aegis/alert-state.json

# /etc/systemd/system/aegis-alert.timer
[Timer]
OnBootSec=300s
OnUnitActiveSec=300s
[Install]
WantedBy=timers.target
```

`systemctl daemon-reload && systemctl enable --now aegis-alert.timer`。
启用真实推送：在 collector.env 加 `AEGIS_ALERT_WEBHOOK=<url>`（可选 `AEGIS_ALERT_FORMAT=dingtalk`），
或给 service 加 `Environment=AEGIS_ALERT_WEBHOOK=...`。未配置即 dry-run（journal 可见评估结果）。

## 配置项（env / 参数）

`AEGIS_COLLECTOR_URL`（默认 http://127.0.0.1:8931）、`AEGIS_COLLECTOR_TOKEN`、`AEGIS_ALERT_WEBHOOK`、
`AEGIS_ALERT_FORMAT`、`AEGIS_ALERT_STATE`；参数 `--offline-hours`、`--min-interval-hours`、`--state`、`--dry-run`。
真实地址/凭据只经 env 传入；仓库只留占位默认。

## 烟雾验证

临时起一个本地 sink 并手动跑一次（带 token）：

```
python3 - <<'PY' &   # 127.0.0.1:9999 接收并落盘 /tmp/alert-sink-got.json
...http.server sink...
PY
set -a; . /etc/aegis/collector.env; set +a
python3 /opt/aegis/aegis_alert_check.py --webhook http://127.0.0.1:9999/ --state /tmp/alert-state-smoke.json
```

期望：打印若干 `ALERT ...` 且 `webhook posted status=200`，sink 收到 `aegis.alert/v1` 载荷；随后删除 sink 与临时 state。

## 运维注意

- 评估器只在 timer/手动触发时运行；collector/console 代码零改动，风险隔离。
- 告警是"提示"不是"处置"：收到 `self_update_failed` 先 `run_canary_release.py --status` 看队列并考虑 `--rollback`；
  收到 `critical_findings` 走风险中心/工单流程；`device_offline` 先恢复端点再判断是否误报。
- 单测：`tests/test_alert_check.py`（条件/去重节流/generic+dingtalk payload，含本地 sink）。
