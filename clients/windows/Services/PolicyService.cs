// PolicyService：企业安全基线（aegis.policy/v1）加载与热更新。
// - 从 %PROGRAMDATA%\AegisAgent\policy.json 读取（Intune 下发）
// - FileSystemWatcher 监听变更并热加载
// - 解析/校验失败时回退到 last-known-good（对应 Python reload_policy 的行为）
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AegisAgent.Services;

/// 校验后的策略对象，类型化访问器与 Python policy.get(...) 一一对应。
public sealed class Policy
{
    private readonly Dictionary<string, JsonElement> _root;

    internal Policy(Dictionary<string, JsonElement> root) => _root = root;

    public string Version => GetString("version") ?? "";

    private string? GetString(string key) =>
        _root.TryGetValue(key, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private List<string>? GetStringList(string key) =>
        _root.TryGetValue(key, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Select(v => v.GetString()).Where(s => s is not null).Select(s => s!).ToList()
            : null;

    public List<string>? AllowedSkills => GetStringList("allowed_skills");
    public List<string>? AllowedMcpServers => GetStringList("allowed_mcp_servers");
    public List<string>? AllowedMcpCommands => GetStringList("allowed_mcp_commands");
    public List<string>? AllowedMcpCommandPaths => GetStringList("allowed_mcp_command_paths");
    public List<string>? AllowedMcpDomains => GetStringList("allowed_mcp_domains");
    public List<string>? AllowedMcpTransports => GetStringList("allowed_mcp_transports");
    public List<string> BlockedCommands => GetStringList("blocked_commands") ?? new();
    public List<string> SecretPatterns => GetStringList("secret_patterns") ?? new();
    public HashSet<string> CodeRules => (GetStringList("code_rules") ?? new()).ToHashSet();

    /// allowed_mcp_invocations：[[command, arg...], ...]
    public HashSet<string> AllowedMcpInvocations
    {
        get
        {
            var result = new HashSet<string>();
            if (_root.TryGetValue("allowed_mcp_invocations", out var value) &&
                value.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in value.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Array)
                    {
                        result.Add(string.Join("\u0000", item.EnumerateArray().Select(v => v.GetString() ?? "")));
                    }
                }
            }
            return result;
        }
    }

    public string EnforcementAction(string key, string fallback = "audit")
    {
        if (_root.TryGetValue("enforcement", out var enforcement) &&
            enforcement.ValueKind == JsonValueKind.Object &&
            enforcement.TryGetProperty(key, out var action) &&
            action.ValueKind == JsonValueKind.String)
        {
            return action.GetString() ?? fallback;
        }
        return fallback;
    }

    /// limits.max_file_bytes，clamp 到 64KB...10MB（与 Python max_file_bytes 一致）。
    public int MaxFileBytes
    {
        get
        {
            var value = 1_000_000;
            if (_root.TryGetValue("limits", out var limits) &&
                limits.ValueKind == JsonValueKind.Object &&
                limits.TryGetProperty("max_file_bytes", out var raw) &&
                raw.TryGetInt32(out var parsed))
            {
                value = parsed;
            }
            return Math.Clamp(value, 65_536, 10_000_000);
        }
    }

    /// limits.project_files，clamp 到 100...100000（与 Python scan 一致）。
    public int ProjectFileLimit
    {
        get
        {
            var value = 10_000;
            if (_root.TryGetValue("limits", out var limits) &&
                limits.ValueKind == JsonValueKind.Object &&
                limits.TryGetProperty("project_files", out var raw) &&
                raw.TryGetInt32(out var parsed))
            {
                value = parsed;
            }
            return Math.Clamp(value, 100, 100_000);
        }
    }
}

public sealed class PolicyService : IDisposable
{
    private readonly string _path;
    private FileSystemWatcher? _watcher;
    private readonly object _gate = new();

    /// 当前生效策略；热加载失败时保持 last-known-good。
    public Policy? Current { get; private set; }

    /// 最近一次热加载是否失败（用于在报告中追加 policy_reload_failed 发现项）。
    public bool LastReloadFailed { get; private set; }

    /// 策略变更事件（可能在 FileSystemWatcher 线程触发，UI 侧需自行调度）。
    public event Action<Policy>? PolicyChanged;

    public PolicyService(string path) => _path = path;

    /// 首次加载；文件缺失或非法时抛出异常（与 Python "valid Aegis policy is required" 一致）。
    public void LoadInitial()
    {
        Current = ParsePolicyFile(_path);
        StartWatching();
    }

    private void StartWatching()
    {
        var directory = Path.GetDirectoryName(_path);
        if (string.IsNullOrEmpty(directory))
        {
            return;
        }
        Directory.CreateDirectory(directory);
        _watcher = new FileSystemWatcher(directory, Path.GetFileName(_path))
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.CreationTime,
            EnableRaisingEvents = true,
        };
        FileSystemEventHandler handler = (_, _) => Reload();
        _watcher.Changed += handler;
        _watcher.Created += handler;
        _watcher.Renamed += handler;
    }

    private void Reload()
    {
        try
        {
            // 原子写入替换时文件可能短暂不可读：小延迟后重试一次。
            System.Threading.Thread.Sleep(200);
            var policy = ParsePolicyFile(_path);
            lock (_gate)
            {
                Current = policy;
                LastReloadFailed = false;
            }
            PolicyChanged?.Invoke(policy);
        }
        catch (Exception)
        {
            // 回退 last-known-good，置位失败标记。
            lock (_gate)
            {
                LastReloadFailed = true;
            }
        }
    }

    /// 读取并校验策略文件（对应 Python validate_policy）。
    public static Policy ParsePolicyFile(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("invalid_policy_contract");
        }

        var root = new Dictionary<string, JsonElement>();
        foreach (var property in document.RootElement.EnumerateObject())
        {
            root[property.Name] = property.Value.Clone();
        }

        if (!root.TryGetValue("schema", out var schema) || schema.GetString() != "aegis.policy/v1" ||
            !root.TryGetValue("version", out var version) ||
            version.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(version.GetString()))
        {
            throw new InvalidDataException("invalid_policy_contract");
        }

        string[] stringLists =
        [
            "allowed_skills", "allowed_mcp_transports", "allowed_mcp_servers", "allowed_mcp_commands",
            "allowed_mcp_command_paths", "allowed_mcp_domains", "blocked_commands", "secret_patterns",
            "skill_rules", "mcp_rules", "code_rules",
        ];
        foreach (var key in stringLists)
        {
            if (!root.TryGetValue(key, out var value))
            {
                continue;
            }
            if (value.ValueKind != JsonValueKind.Array ||
                value.EnumerateArray().Any(item => item.ValueKind != JsonValueKind.String))
            {
                throw new InvalidDataException($"invalid_policy_list:{key}");
            }
        }

        // 预编译校验所有 secret_patterns 正则。
        if (root.TryGetValue("secret_patterns", out var patterns) && patterns.ValueKind == JsonValueKind.Array)
        {
            foreach (var pattern in patterns.EnumerateArray())
            {
                try
                {
                    _ = new Regex(pattern.GetString() ?? "");
                }
                catch (ArgumentException)
                {
                    throw new InvalidDataException("invalid_policy_regex");
                }
            }
        }

        // TODO: 校验 allowed_mcp_invocations 为 [[非空字符串, ...>=2], ...]。
        return new Policy(root);
    }

    public void Dispose()
    {
        _watcher?.Dispose();
        _watcher = null;
    }
}
