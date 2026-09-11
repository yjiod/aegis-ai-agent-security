// ScannerService：aegis_agent.py 核心扫描逻辑的 C# 移植（骨架）。
// 报告契约保持 aegis.report/v1；只读扫描，绝不执行被发现的 Agent。
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AegisAgent.Models;

namespace AegisAgent.Services;

public sealed partial class ScannerService
{
    public const string AgentVersion = "0.30.0";

    /// 报告条目上限（与 Python REPORT_INVENTORY_LIMIT / REPORT_FINDING_LIMIT 一致）。
    private const int InventoryLimit = 5_000;
    private const int FindingLimit = 10_000;

    private readonly AgentConfig _config;
    private readonly string _home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private readonly string _appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private readonly string _localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    /// 用户级发现标记（Windows 安装位置）。
    private static readonly (string Name, string Path, string Scope)[] AgentMarkers =
    [
        ("cursor", @"%APPDATA%\Cursor", "user"),
        ("claude_code", @"%USERPROFILE%\.claude", "user"),
        ("codex", @"%APPDATA%\codex", "user"),
        ("windsurf", @"%APPDATA%\Windsurf", "user"),
        // 与 Python 原型相同的 dotfile 标记（跨端一致）。
        ("cursor", @"%USERPROFILE%\.cursor\mcp.json", "user"),
        ("claude_code", @"%USERPROFILE%\.claude.json", "user"),
        ("codex", @"%USERPROFILE%\.codex\config.toml", "user"),
        ("windsurf", @"%USERPROFILE%\.codeium\windsurf\mcp_config.json", "user"),
    ];

    /// Agent 配置文件（逐个做文本 + MCP 扫描）。
    private static readonly string[] AgentConfigs =
    [
        @"%USERPROFILE%\.cursor\mcp.json",
        @"%USERPROFILE%\.claude.json",
        @"%USERPROFILE%\.codex\config.toml",
        @"%USERPROFILE%\.codeium\windsurf\mcp_config.json",
    ];

    /// Skill 根目录。
    private static readonly string[] SkillRoots =
    [
        @"%USERPROFILE%\.codex\skills",
        @"%USERPROFILE%\.claude\skills",
        @"%USERPROFILE%\.cursor\skills",
    ];

    private static readonly HashSet<string> DependencyManifests = ["package.json", "requirements.txt", "requirements-dev.txt"];

    private static readonly HashSet<string> ReadableExtensions =
        [".md", ".txt", ".py", ".js", ".ts", ".tsx", ".jsx", ".sh", ".ps1", ".json", ".toml", ".yaml", ".yml"];

    private static readonly HashSet<string> CodeExtensions =
        [".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".php", ".sh", ".json", ".toml", ".yaml", ".yml"];

    private static readonly HashSet<string> SkippedDirectories =
        [".git", "node_modules", "vendor", "dist", "build", ".venv"];

    public ScannerService(AgentConfig config) => _config = config;

    // MARK: 路径脱敏与发现项构造

    /// 将用户目录前缀替换为 "~"（对应 Python safe_path）。
    private string SafePath(string path) =>
        path.StartsWith(_home, StringComparison.OrdinalIgnoreCase)
            ? "~" + path[_home.Length..]
            : path;

    private Finding MakeFinding(string kind, string severity, string path, string message, string evidence = "") =>
        new(kind, severity, SafePath(path), message, Truncate(evidence, 180));

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];

    private string Expand(string path) =>
        Environment.ExpandEnvironmentVariables(path.Replace("%APPDATA%", _appData)
            .Replace("%USERPROFILE%", _home).Replace("%LOCALAPPDATA%", _localAppData));

    /// 通过文件系统标记发现 AI 编码工具；只检查存在性，绝不执行。
    public List<Inventory> DiscoverAgents()
    {
        var found = new List<Inventory>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, rawPath, scope) in AgentMarkers)
        {
            var path = Expand(rawPath);
            if (!File.Exists(path) && !Directory.Exists(path))
            {
                continue;
            }
            var key = $"{name}|{path}";
            if (seen.Add(key))
            {
                found.Add(new Inventory { Type = "ai_agent", Name = name, Path = SafePath(path), Scope = scope, DetectedBy = "filesystem_marker" });
            }
        }
        return found;
    }

    // MARK: 文本扫描

    /// 通用文本规则（对应 Python scan_text）。返回 (kind, severity, pattern, 匹配目标 lower/text) 命中。
    public List<Finding> ScanText(string path, string text, Policy policy)
    {
        var findings = new List<Finding>();
        var lower = text.ToLowerInvariant();

        // 基础行为规则（在 lowercase 文本上匹配）。
        (string Kind, string Severity, string Pattern)[] behaviorChecks =
        [
            ("prompt_override", "high", @"ignore (all |any )?(previous|prior) instructions"),
            ("credential_access", "high", @"(?:~/|\$home/)(?:\.ssh|\.aws)|security\s+find-(?:generic|internet)-password"),
            ("unbounded_shell", "high", @"shell\s*=\s*true|subprocess\..*shell\s*=\s*true"),
            ("dynamic_eval", "medium", @"\beval\s*\(|\bexec\s*\("),
        ];
        foreach (var (kind, severity, pattern) in behaviorChecks)
        {
            var match = Regex.Match(lower, pattern);
            if (match.Success)
            {
                findings.Add(MakeFinding(kind, severity, path, $"匹配规则 {pattern}", match.Value));
            }
        }

        // 代码质量规则：仅当策略 code_rules 启用对应 kind 时执行。
        (string Kind, string Severity, string Pattern)[] qualityChecks =
        [
            ("insecure_tls_verification", "critical",
             @"(?is)\brequests\.(?:get|post|put|patch|delete|request)\s*\([^)]{0,500}\bverify\s*=\s*false|rejectunauthorized\s*:\s*false|node_tls_reject_unauthorized\s*=\s*['""]?0"),
            ("unsafe_deserialization", "high",
             @"(?i)\bpickle\.loads?\s*\(|\bbinaryformatter\s*\(|\bobjectinputstream\s*\("),
            ("debug_mode_enabled", "medium",
             @"(?is)\b(?:app|application)\.run\s*\([^)]{0,300}\bdebug\s*=\s*true"),
            ("empty_exception_handler", "medium",
             @"(?m)^\s*except(?:\s+[^:]+)?:\s*(?:#.*\n\s*)?pass\s*$|\bcatch\s*\{\s*\}"),
        ];
        foreach (var (kind, severity, pattern) in qualityChecks)
        {
            if (!policy.CodeRules.Contains(kind))
            {
                continue;
            }
            var match = Regex.Match(text, pattern);
            if (match.Success)
            {
                findings.Add(MakeFinding(kind, severity, path, $"安全代码质量规则命中: {kind}", Truncate(match.Value.Trim(), 80)));
            }
        }

        // 隐藏 / 双向 Unicode 控制字符。
        foreach (var ch in text)
        {
            if (ch is >= '\u200B' and <= '\u200F' or >= '\u202A' and <= '\u202E'
                || ch is '\u2060' or >= '\u2066' and <= '\u2069' or '\uFEFF')
            {
                findings.Add(MakeFinding("hidden_instruction", "high", path,
                    "包含可隐藏或改变显示方向的 Unicode 控制字符", $"U+{(int)ch:X4}"));
                break;
            }
        }

        // 安全敏感值使用非密码学随机数。
        if (Regex.IsMatch(text, @"(?is)(?:token|secret|session|nonce).{0,120}(?:math\.random|random\.random)\s*\(|(?:math\.random|random\.random)\s*\(.{0,120}(?:token|secret|session|nonce)"))
        {
            findings.Add(MakeFinding("weak_random_token", "high", path, "安全敏感值使用非密码学随机数", "weak random generator"));
        }

        // 禁止命令（策略下发，支持 * 通配）。
        foreach (var command in policy.BlockedCommands)
        {
            var pattern = "(?m)^\\s*" + Regex.Escape(command.ToLowerInvariant()).Replace(@"\*", @"[^\r\n]*") + @"(?:\s|$)";
            var match = Regex.Match(lower, pattern);
            if (match.Success)
            {
                findings.Add(MakeFinding("blocked_command", "high", path, $"命中禁止命令: {command}", Truncate(match.Value.Trim(), 80)));
            }
        }

        // 硬编码凭据（策略下发正则）。
        foreach (var pattern in policy.SecretPatterns)
        {
            Match match;
            try
            {
                match = Regex.Match(text, pattern);
            }
            catch (ArgumentException)
            {
                var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pattern)))[..12].ToLowerInvariant();
                findings.Add(MakeFinding("invalid_policy_regex", "high", path, "策略包含无效的敏感信息正则", digest));
                continue;
            }
            if (match.Success)
            {
                findings.Add(MakeFinding("hardcoded_secret", "critical", path, "疑似硬编码凭据", Truncate(match.Value, 8) + "…"));
            }
        }
        return findings;
    }

    // MARK: MCP 扫描

    /// 扫描 MCP 配置文件（JSON 顶层 mcpServers/servers）。
    public List<Finding> ScanMcp(string path, Policy policy)
    {
        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception)
        {
            return [MakeFinding("unreadable", "low", path, "配置存在但无法读取")];
        }

        if (Path.GetExtension(path).Equals(".toml", StringComparison.OrdinalIgnoreCase))
        {
            // TODO: 移植 Python 的 TOML 正则解析（[mcp_servers.name] 段 + 明文密钥行扫描）。
            return [];
        }
        if (!Path.GetExtension(path).Equals(".json", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(text);
        }
        catch (Exception)
        {
            return [MakeFinding("invalid_mcp_config", "medium", path, "MCP JSON 配置无法安全解析")];
        }
        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return [MakeFinding("invalid_mcp_config", "medium", path, "MCP JSON 顶层必须是对象")];
            }
            JsonElement servers = default;
            var hasServers = document.RootElement.TryGetProperty("mcpServers", out servers) ||
                             document.RootElement.TryGetProperty("servers", out servers);
            if (!hasServers || servers.ValueKind != JsonValueKind.Object)
            {
                return [MakeFinding("invalid_mcp_config", "medium", path, "MCP Server 集合必须是对象")];
            }

            var findings = new List<Finding>();
            foreach (var server in servers.EnumerateObject())
            {
                if (server.Value.ValueKind != JsonValueKind.Object)
                {
                    findings.Add(MakeFinding("invalid_mcp_server", "high", path, $"MCP Server {server.Name} 配置必须是对象"));
                    continue;
                }
                findings.AddRange(ScanMcpServer(path, server.Name, server.Value, policy));
            }
            return findings;
        }
    }

    /// 扫描单个 MCP Server 配置（对应 Python scan_mcp_server）。
    private List<Finding> ScanMcpServer(string path, string name, JsonElement cfg, Policy policy)
    {
        var findings = new List<Finding>();
        var command = GetString(cfg, "command").Trim();
        var url = (GetString(cfg, "url").Length > 0 ? GetString(cfg, "url") : GetString(cfg, "serverUrl")).Trim();
        var explicitTransport = GetString(cfg, "transport").ToLowerInvariant();
        var transport = explicitTransport.Length > 0 ? explicitTransport
            : url.StartsWith("https://") ? "https"
            : url.StartsWith("http://") ? "http"
            : command.Length > 0 ? "stdio"
            : "unknown";

        if (policy.AllowedMcpServers is { } allowedServers && !allowedServers.Contains(name))
        {
            findings.Add(MakeFinding("unknown_mcp", "medium", path, $"未在允许列表中的 MCP Server: {name}"));
        }
        if (command.Length > 0 && url.Length > 0)
        {
            findings.Add(MakeFinding("ambiguous_mcp_transport", "high", path, $"MCP {name} 同时配置本地命令和远程 URL"));
        }
        if (policy.AllowedMcpTransports is { } allowedTransports && !allowedTransports.Contains(transport))
        {
            findings.Add(MakeFinding("unapproved_mcp_transport", "high", path, $"MCP {name} 使用未批准传输: {transport}"));
        }
        var baseName = command.Split(['/', '\\']).LastOrDefault() ?? "";
        if (command.Length > 0 && policy.AllowedMcpCommands is { } allowedCommands && !allowedCommands.Contains(baseName))
        {
            findings.Add(MakeFinding("unapproved_mcp_command", "high", path, $"MCP 使用未批准命令: {baseName}"));
        }

        var args = new List<string>();
        if (cfg.TryGetProperty("args", out var rawArgs))
        {
            if (rawArgs.ValueKind != JsonValueKind.Array)
            {
                findings.Add(MakeFinding("invalid_mcp_arguments", "high", path, $"MCP {name} 的 args 必须是数组"));
            }
            else
            {
                args = rawArgs.EnumerateArray()
                    .Where(v => v.ValueKind is JsonValueKind.String or JsonValueKind.Number)
                    .Select(v => v.ValueKind == JsonValueKind.String ? v.GetString()! : v.GetRawText())
                    .ToList();
            }
        }
        if (command.Length > 0 && args.Count > 0 &&
            !policy.AllowedMcpInvocations.Contains(string.Join("\u0000", [baseName, .. args])))
        {
            findings.Add(MakeFinding("unapproved_mcp_invocation", "high", path, $"MCP {name} 的命令参数组合未获批准"));
        }
        // TODO: allowed_mcp_command_paths 校验（Windows 路径需 normcase + normpath 后比较）。
        if (args.Any(a => a is "/" or @"C:\" or "$HOME" or "~" ||
                          a.StartsWith("/Users/") || a.StartsWith("/home/")))
        {
            findings.Add(MakeFinding("broad_filesystem_scope", "high", path, $"MCP {name} 请求宽泛文件范围"));
        }

        if (cfg.TryGetProperty("env", out var env))
        {
            if (env.ValueKind != JsonValueKind.Object)
            {
                findings.Add(MakeFinding("invalid_mcp_environment", "high", path, $"MCP {name} 的 env 必须是对象"));
            }
            else
            {
                foreach (var variable in env.EnumerateObject())
                {
                    if (!Regex.IsMatch(variable.Name, "TOKEN|SECRET|PASSWORD|API_KEY", RegexOptions.IgnoreCase))
                    {
                        continue;
                    }
                    var value = variable.Value.ValueKind == JsonValueKind.String ? variable.Value.GetString() ?? "" : "";
                    if (value.Length > 0 && !Regex.IsMatch(value, @"^\$\{?[A-Z0-9_]+\}?$"))
                    {
                        findings.Add(MakeFinding("literal_mcp_secret", "critical", path,
                            $"MCP {name} 包含明文敏感环境变量: {variable.Name}", "[REDACTED]"));
                    }
                }
            }
        }

        if (url.Length > 0)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed))
            {
                findings.Add(MakeFinding("invalid_mcp_url", "high", path, $"MCP {name} URL 无法解析"));
            }
            else
            {
                var host = parsed.Host.ToLowerInvariant().TrimEnd('.');
                if (parsed.Scheme != "https://".TrimEnd("://".ToCharArray()) && parsed.Scheme != Uri.UriSchemeHttps)
                {
                    findings.Add(MakeFinding("insecure_mcp_transport", "high", path, $"MCP {name} 未使用 HTTPS"));
                }
                if (policy.AllowedMcpDomains is { } allowedDomains &&
                    !allowedDomains.Select(d => d.ToLowerInvariant().TrimEnd('.')).Contains(host))
                {
                    findings.Add(MakeFinding("unapproved_mcp_domain", "medium", path,
                        $"MCP {name} 连接未批准域名: {(host.Length > 0 ? host : "[missing]")}"));
                }
                string[] sensitive = ["token", "key", "api_key", "apikey", "secret", "password", "access_token"];
                var query = System.Web.HttpUtility.ParseQueryString(parsed.Query);
                var queryHasSecret = query.AllKeys.Any(k => k is not null && sensitive.Contains(k.ToLowerInvariant()));
                if (!string.IsNullOrEmpty(parsed.UserInfo) || queryHasSecret)
                {
                    findings.Add(MakeFinding("mcp_url_credentials", "critical", path,
                        $"MCP {name} URL 包含凭据或敏感查询参数", "[REDACTED]"));
                }
            }
        }
        if (command.Length == 0 && url.Length == 0)
        {
            findings.Add(MakeFinding("incomplete_mcp_server", "medium", path, $"MCP {name} 未配置命令或 URL"));
        }
        return findings;
    }

    private static string GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? ""
            : "";

    // MARK: Skill 扫描

    /// 扫描单个 Skill 包目录：不跟随指向包外的符号链接，文件数上限 500。
    private (List<Finding> Findings, int Scanned) ScanSkillPackage(string skillDirectory, Policy policy, int maxFiles = 500)
    {
        var name = Path.GetFileName(skillDirectory);
        var findings = new List<Finding>();
        var scanned = 0;

        if (policy.AllowedSkills is { } allowed && !allowed.Contains(name))
        {
            var action = policy.EnforcementAction("unknown_skill", "audit");
            var severity = action == "block" ? "high" : "medium";
            findings.Add(MakeFinding("unknown_skill", severity, Path.Combine(skillDirectory, "SKILL.md"), $"未批准的 Skill: {name}"));
        }

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(skillDirectory, "*", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.Hidden,
            });
        }
        catch (Exception)
        {
            return (findings, scanned);
        }

        foreach (var file in files)
        {
            if (scanned >= maxFiles)
            {
                findings.Add(MakeFinding("skill_scan_truncated", "medium", skillDirectory, $"Skill 文件数超过扫描上限 {maxFiles}"));
                break;
            }
            // TODO: 剪枝 .git/node_modules/vendor/dist/build；
            //       符号链接（reparse point）resolve 后若逃出 Skill 根目录，报 skill_symlink_escape。
            if (SkippedDirectories.Contains(Path.GetFileName(Path.GetDirectoryName(file)) ?? ""))
            {
                continue;
            }
            if (!ReadableExtensions.Contains(Path.GetExtension(file).ToLowerInvariant()))
            {
                continue;
            }
            scanned++;
            try
            {
                var info = new FileInfo(file);
                if (info.Length > policy.MaxFileBytes)
                {
                    findings.Add(MakeFinding("oversized_file_skipped", "medium", file,
                        $"Skill 文件超过扫描字节上限 {policy.MaxFileBytes}", info.Length.ToString()));
                    continue;
                }
                var text = File.ReadAllText(file);
                findings.AddRange(ScanText(file, text, policy));
                if (DependencyManifests.Contains(Path.GetFileName(file)))
                {
                    findings.AddRange(ScanDependencyManifest(file, text));
                }
            }
            catch (Exception)
            {
                findings.Add(MakeFinding("unreadable", "low", file, "Skill 文件存在但无法读取"));
            }
        }
        return (findings, scanned);
    }

    /// 遍历所有 Skill 根目录，扫描每个 SKILL.md 所在包。
    public (List<Finding> Findings, List<Inventory> Inventory) ScanSkills(Policy policy)
    {
        var findings = new List<Finding>();
        var inventory = new List<Inventory>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rawRoot in SkillRoots)
        {
            var root = Expand(rawRoot);
            if (!Directory.Exists(root))
            {
                continue;
            }
            IEnumerable<string> skillFiles;
            try
            {
                skillFiles = Directory.EnumerateFiles(root, "SKILL.md", new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    IgnoreInaccessible = true,
                });
            }
            catch (Exception)
            {
                continue;
            }
            foreach (var skillFile in skillFiles.Where(f => !f.Contains(@"\.system\", StringComparison.OrdinalIgnoreCase)))
            {
                var skillDirectory = Path.GetDirectoryName(skillFile)!;
                if (!seen.Add(Path.GetFullPath(skillDirectory)))
                {
                    continue;
                }
                var approved = policy.AllowedSkills?.Contains(Path.GetFileName(skillDirectory)) ?? false;
                var (packageFindings, scanned) = ScanSkillPackage(skillDirectory, policy);
                inventory.Add(new Inventory
                {
                    Type = "skill",
                    Name = Path.GetFileName(skillDirectory),
                    Path = SafePath(skillFile),
                    Approved = approved,
                    ScannedFiles = scanned,
                });
                findings.AddRange(packageFindings);
            }
        }
        return (findings, inventory);
    }

    // MARK: 代码质量扫描

    /// 基础 SAST：遍历扫描根目录，对候选文件执行文本规则 + MCP/依赖清单检查。
    public (List<Finding> Findings, List<Inventory> Inventory) ScanCodeQuality(string root, Policy policy)
    {
        var findings = new List<Finding>();
        var inventory = new List<Inventory>();
        var scanned = 0;
        var truncated = false;
        var fileLimit = policy.ProjectFileLimit;

        foreach (var file in EnumerateCodeFiles(root))
        {
            if (scanned >= fileLimit)
            {
                truncated = true;
                break;
            }
            var extension = Path.GetExtension(file).ToLowerInvariant();
            var isManifest = DependencyManifests.Contains(Path.GetFileName(file));
            if (!CodeExtensions.Contains(extension) && !isManifest)
            {
                continue;
            }
            scanned++;
            try
            {
                var info = new FileInfo(file);
                if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    continue;
                }
                if (info.Length > policy.MaxFileBytes)
                {
                    findings.Add(MakeFinding("oversized_file_skipped", "medium", file,
                        $"代码或配置文件超过扫描字节上限 {policy.MaxFileBytes}", info.Length.ToString()));
                    continue;
                }
                var text = File.ReadAllText(file);
                findings.AddRange(ScanText(file, text, policy));
                var name = Path.GetFileName(file);
                if (name is "mcp.json" or "mcp_config.json" or "config.toml")
                {
                    findings.AddRange(ScanMcp(file, policy));
                }
                if (isManifest)
                {
                    inventory.Add(new Inventory { Type = "dependency_manifest", Path = SafePath(file) });
                    findings.AddRange(ScanDependencyManifest(file, text));
                }
            }
            catch (Exception)
            {
                // 不可读文件静默跳过（与 Python 主扫描循环一致）。
            }
        }
        if (truncated)
        {
            findings.Add(MakeFinding("project_scan_truncated", "medium", root, $"项目候选文件超过扫描上限 {fileLimit}"));
        }
        return (findings, inventory);
    }

    /// 手动栈式遍历以便剪枝 .git/node_modules 等目录。
    private static IEnumerable<string> EnumerateCodeFiles(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            IEnumerable<string> directories;
            IEnumerable<string> files;
            try
            {
                directories = Directory.EnumerateDirectories(current);
                files = Directory.EnumerateFiles(current);
            }
            catch (Exception)
            {
                continue;
            }
            foreach (var directory in directories)
            {
                if (!SkippedDirectories.Contains(Path.GetFileName(directory)))
                {
                    stack.Push(directory);
                }
            }
            foreach (var file in files)
            {
                yield return file;
            }
        }
    }

    /// 依赖清单检查：远程源码 / 未固定版本 / 缺少锁文件（对应 Python scan_dependency_manifest）。
    public List<Finding> ScanDependencyManifest(string path, string text)
    {
        var findings = new List<Finding>();
        var name = Path.GetFileName(path);

        if (name == "package.json")
        {
            JsonDocument document;
            try
            {
                document = JsonDocument.Parse(text);
            }
            catch (Exception)
            {
                return [MakeFinding("invalid_dependency_manifest", "medium", path, "package.json 无法安全解析")];
            }
            using (document)
            {
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    return [MakeFinding("invalid_dependency_manifest", "medium", path, "package.json 顶层必须是对象")];
                }
                var dependencies = new Dictionary<string, string>();
                foreach (var key in new[] { "dependencies", "devDependencies", "optionalDependencies", "peerDependencies" })
                {
                    if (document.RootElement.TryGetProperty(key, out var values) && values.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var dependency in values.EnumerateObject())
                        {
                            dependencies[dependency.Name] = dependency.Value.ToString();
                        }
                    }
                }
                foreach (var (dependency, version) in dependencies)
                {
                    var low = version.Trim().ToLowerInvariant();
                    if (Regex.IsMatch(low, @"^(?:https?://|git(?:\+|://)|github:)"))
                    {
                        findings.Add(MakeFinding("dependency_untrusted_source", "high", path, $"依赖 {dependency} 直接使用远程源码", Truncate(version, 80)));
                    }
                    else if (low is "*" or "latest" or "next" || Regex.IsMatch(version, @"^[~^<>=]"))
                    {
                        findings.Add(MakeFinding("dependency_unpinned", "medium", path, $"依赖 {dependency} 未固定到精确版本", Truncate(version, 80)));
                    }
                }
                string[] locks = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"];
                var directory = Path.GetDirectoryName(path)!;
                if (dependencies.Count > 0 && !locks.Any(lockFile => File.Exists(Path.Combine(directory, lockFile))))
                {
                    findings.Add(MakeFinding("missing_lockfile", "medium", path, "JavaScript 依赖缺少受支持的锁文件"));
                }
            }
        }
        else if (name.StartsWith("requirements") && Path.GetExtension(name) == ".txt")
        {
            foreach (var rawLine in text.Split('\n'))
            {
                var value = rawLine.Trim();
                if (value.Length == 0 || value.StartsWith('#'))
                {
                    continue;
                }
                if (Regex.IsMatch(value, @"^(?:-e\s+)?(?:https?://|git\+)", RegexOptions.IgnoreCase))
                {
                    findings.Add(MakeFinding("dependency_untrusted_source", "high", path, "Python 依赖直接使用远程源码", Truncate(value, 80)));
                }
                else if (value.StartsWith("-r ") || value.StartsWith("--requirement "))
                {
                    findings.Add(MakeFinding("dependency_external_manifest", "medium", path, "Python 依赖引用其他清单，需纳入审核", Truncate(value, 80)));
                }
                else if (!value.Contains("=="))
                {
                    findings.Add(MakeFinding("dependency_unpinned", "medium", path, "Python 依赖未固定到精确版本", Truncate(value, 80)));
                }
            }
        }
        return findings;
    }

    // MARK: 报告组装

    /// 完整扫描一轮并组装 aegis.report/v1 报告。
    public AegisReport BuildReport(Policy policy)
    {
        var findings = new List<Finding>();
        var inventory = new List<Inventory>();

        inventory.AddRange(DiscoverAgents());

        // Agent 配置文件扫描。
        foreach (var rawPath in AgentConfigs)
        {
            var path = Expand(rawPath);
            if (!File.Exists(path))
            {
                continue;
            }
            inventory.Add(new Inventory { Type = "agent_config", Path = SafePath(path) });
            try
            {
                var info = new FileInfo(path);
                if (info.Length > policy.MaxFileBytes)
                {
                    findings.Add(MakeFinding("oversized_file_skipped", "medium", path,
                        $"Agent 配置超过扫描字节上限 {policy.MaxFileBytes}", info.Length.ToString()));
                    continue;
                }
                var text = File.ReadAllText(path);
                findings.AddRange(ScanText(path, text, policy));
                findings.AddRange(ScanMcp(path, policy));
            }
            catch (Exception)
            {
                findings.Add(MakeFinding("unreadable", "low", path, "配置存在但无法读取"));
            }
        }

        // Skills 扫描。
        var (skillFindings, skillInventory) = ScanSkills(policy);
        findings.AddRange(skillFindings);
        inventory.AddRange(skillInventory);

        // 工程代码质量扫描。
        var (qualityFindings, qualityInventory) = ScanCodeQuality(_config.ScanRoot, policy);
        findings.AddRange(qualityFindings);
        inventory.AddRange(qualityInventory);

        // 清单 / 发现项上限截断（与 Python build_report 一致）。
        if (inventory.Count > InventoryLimit)
        {
            var omitted = inventory.Count - InventoryLimit + 1;
            inventory = [.. inventory.Take(InventoryLimit - 1), new Inventory { Type = "inventory_truncated" }];
            _ = omitted; // TODO: Python 端将 omitted 写入截断项；保持 schema 兼容时按需补充。
        }
        if (findings.Count > FindingLimit)
        {
            var omitted = findings.Count - FindingLimit + 1;
            findings = [.. findings.Take(FindingLimit - 1),
                MakeFinding("findings_truncated", "medium", _config.ScanRoot, $"报告发现项超限，省略 {omitted} 项")];
        }

        return new AegisReport
        {
            PolicyVersion = policy.Version,
            DeviceId = _config.DeviceId,
            ScannedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ScanRoot = SafePath(_config.ScanRoot),
            Inventory = inventory,
            Summary = Summary.FromFindings(findings),
            Findings = findings,
        };
    }
}
