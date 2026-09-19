// AegisExecGuard — Endpoint Security AUTH_EXEC 执行级封禁守护。
//
// 定位(调研结论): mac 上 per-process 的"执行"预防性拦截, 在 SIP 开启前提下唯一官方路径是
// Endpoint Security 的 AUTH_EXEC(网络 per-process 则需 NEFilterDataProvider 系统扩展, 另立项)。
// 本守护订阅 AUTH_EXEC, 对 deny-list 中的可执行路径返回 ES_AUTH_RESULT_DENY(操作系统级拒绝,
// 先于进程启动, 无滞后), 其余一律 ALLOW(白名单之外零影响)。
//
// 限度内行为(用户约束: 不可能关 SIP):
//   - ES 客户端需要 com.apple.developer.endpoint-security.client entitlement(Apple 审批)+
//     Developer ID 签名; 未授权/未签名时 es_new_client 返回 NOT_ENTITLED → 本守护**优雅退出
//     (exit 2)** 并在 stderr 说明, 终端 Agent 回退到 chmod exec-deny(已有能力), 功能不中断。
//   - 不要求关 SIP; AUTH_EXEC 在 SIP 开启下即可用(只要 entitlement 到位)。
//   - 只 DENY deny-list 内路径; deny-list 由终端 Agent 从**签名策略 deny 名单**写出
//     (~/.aegis-exec-deny-list.json), 人工审批语义不变。
//   - 每次 DENY 追加一条 jsonl 到 ~/.aegis-quarantine/.aegis-es-deny.log, 终端 Agent 读取
//     生成回执(exec_blocked_es)上报控制台。
//
// 用法: AegisExecGuard [denyListPath] [eventLogPath]
import EndpointSecurity
import Foundation

let args = CommandLine.arguments
let denyListPath = args.count > 1 ? args[1] : (NSHomeDirectory() + "/.aegis-exec-deny-list.json")
let eventLogPath = args.count > 2 ? args[2] : (NSHomeDirectory() + "/.aegis-quarantine/.aegis-es-deny.log")
let statusPath = "/Library/Application Support/AegisAgent/.aegis-es-status.json"

// 自报状态供终端上报 capabilities.es(能力诚实化): active=已订阅 AUTH_EXEC; degraded=未授权/未签名回退。
func writeStatus(_ state: String, _ reason: String) {
    let json = "{\"state\":\"\(state)\",\"reason\":\"\(reason)\",\"at\":\(Int(Date().timeIntervalSince1970))}\n"
    if let data = json.data(using: .utf8) {
        try? data.write(to: URL(fileURLWithPath: statusPath))
        chmod(statusPath, 0o644)
    }
}

var denySet: Set<String> = []
var listMtimes: [String: TimeInterval] = [:]

// deny-list 由终端 Agent 写在各自 home; 守护以 root 运行, 联合读取所有候选(含 /var/root),
// 避免 root/用户 home 不一致导致名单看不见。
func candidateDenyLists() -> [String] {
    var c = [denyListPath, "/var/root/.aegis-exec-deny-list.json"]
    if let users = try? FileManager.default.contentsOfDirectory(atPath: "/Users") {
        for u in users { c.append("/Users/\(u)/.aegis-exec-deny-list.json") }
    }
    return c
}

func reloadDenyList() {
    let fm = FileManager.default
    var union: Set<String> = []
    for path in candidateDenyLists() {
        guard fm.fileExists(atPath: path) else { continue }
        guard let attrs = try? fm.attributesOfItem(atPath: path),
              let mt = attrs[.modificationDate] as? Date else { continue }
        let ts = mt.timeIntervalSince1970
        if listMtimes[path] == ts { 
            if let data = fm.contents(atPath: path),
               let arr = (try? JSONSerialization.jsonObject(with: data)) as? [String] { union.formUnion(arr) }
            continue
        }
        listMtimes[path] = ts
        if let data = fm.contents(atPath: path),
           let arr = (try? JSONSerialization.jsonObject(with: data)) as? [String] {
            union.formUnion(arr)
        }
    }
    denySet = union
}

func logDeny(_ path: String) {
    let dir = (eventLogPath as NSString).deletingLastPathComponent
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    let entry = "{\"at\":\(Int(Date().timeIntervalSince1970)),\"action\":\"exec_blocked_es\",\"asset_type\":\"mcp\",\"target\":\"\(path)\"}\n"
    if let data = entry.data(using: .utf8) {
        if FileManager.default.fileExists(atPath: eventLogPath),
           let h = FileHandle(forWritingAtPath: eventLogPath) {
            h.seekToEndOfFile(); h.write(data); h.closeFile()
        } else {
            try? data.write(to: URL(fileURLWithPath: eventLogPath))
        }
    }
}

var client: OpaquePointer?
let newRes = es_new_client(&client) { c, msg in
    switch msg.pointee.event_type {
    case ES_EVENT_TYPE_AUTH_EXEC:
        reloadDenyList()
        let token = msg.pointee.event.exec.target.pointee.executable.pointee.path
        var path = ""
        if let data = token.data {
            path = String(bytes: Data(bytes: data, count: token.length), encoding: .utf8) ?? ""
        }
        if denySet.contains(path) {
            logDeny(path)
            es_respond_auth_result(c, msg, ES_AUTH_RESULT_DENY, false)
        } else {
            es_respond_auth_result(c, msg, ES_AUTH_RESULT_ALLOW, false)
        }
    default:
        es_respond_auth_result(c, msg, ES_AUTH_RESULT_ALLOW, false)
    }
}
guard newRes == ES_NEW_CLIENT_RESULT_SUCCESS, client != nil else {
    writeStatus("degraded", "es_new_client=\(newRes)")
    FileHandle.standardError.write(
        "aegis-exec-guard: es_new_client failed (\(newRes)); likely missing endpoint-security entitlement or signature. Falling back to agent chmod exec-deny.\n".data(using: .utf8)!)
    exit(2)
}
let events: [es_event_type_t] = [ES_EVENT_TYPE_AUTH_EXEC]
let subRes = es_subscribe(client!, events, 1)
guard subRes == ES_RETURN_SUCCESS else {
    writeStatus("degraded", "es_subscribe=\(subRes)")
    FileHandle.standardError.write("aegis-exec-guard: es_subscribe failed (\(subRes))\n".data(using: .utf8)!)
    exit(3)
}
writeStatus("active", "subscribed AUTH_EXEC")
reloadDenyList()
RunLoop.main.run()
