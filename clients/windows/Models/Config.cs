// AgentConfig：Windows 客户端配置。
// 配置文件：%PROGRAMDATA%\AegisAgent\config.json
// 默认值与 Python 原型（aegis_agent.py / reporting.json 契约）保持一致。
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AegisAgent.Models;

public sealed class AgentConfig
{
    /// 配置 schema 标识。
    [JsonPropertyName("schema")] public string Schema { get; set; } = "aegis.config/v1";

    /// Collector 上报地址（必须为 https）；为空表示禁用上报。
    [JsonPropertyName("collector_url")] public string CollectorUrl { get; set; } = "";

    /// Bearer token（Authorization 头），长度 32...4096。
    [JsonPropertyName("report_token")] public string ReportToken { get; set; } = "";

    /// HMAC-SHA256 签名密钥，长度 32...4096，且不得与 ReportToken 相同。
    [JsonPropertyName("signing_secret")] public string SigningSecret { get; set; } = "";

    /// 设备 ID：默认为 sha256(hostname) 前 12 位十六进制（与 Python 端一致）。
    [JsonPropertyName("device_id")] public string DeviceId { get; set; } = DefaultDeviceId();

    /// 周期扫描间隔（秒），默认 3600，下限 60。
    [JsonPropertyName("scan_interval_seconds")] public int ScanIntervalSeconds { get; set; } = 3600;

    /// 扫描根目录，默认为用户目录（%USERPROFILE%）。
    [JsonPropertyName("scan_root")] public string ScanRoot { get; set; } =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    /// 企业策略文件路径（MDM 下发）。
    [JsonPropertyName("policy_path")] public string PolicyPath { get; set; } =
        Path.Combine(ProgramDataDirectory, "policy.json");

    /// 离线队列目录。
    [JsonPropertyName("queue_directory")] public string QueueDirectory { get; set; } =
        Path.Combine(ProgramDataDirectory, "queue");

    /// 离线队列最大保留报告数（Python: AEGIS_SPOOL_MAX_REPORTS，clamp 10...10000）。
    [JsonPropertyName("queue_limit")] public int QueueLimit { get; set; } = 500;

    /// %PROGRAMDATA%\AegisAgent
    public static string ProgramDataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AegisAgent");

    public static string DefaultConfigFile => Path.Combine(ProgramDataDirectory, "config.json");

    /// 与 Python 端一致：device_id = sha256(hostname)[:12]
    public static string DefaultDeviceId()
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(Environment.MachineName));
        return Convert.ToHexString(hash)[..12].ToLowerInvariant();
    }

    /// 上报凭据是否完整可用。
    public bool ReportingEnabled =>
        !string.IsNullOrEmpty(CollectorUrl) &&
        !string.IsNullOrEmpty(ReportToken) &&
        !string.IsNullOrEmpty(SigningSecret);

    /// 从磁盘加载；文件缺失或解析失败时回退到默认值。
    public static AgentConfig Load(string? path = null)
    {
        path ??= DefaultConfigFile;
        try
        {
            if (File.Exists(path))
            {
                var config = JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(path));
                if (config is not null)
                {
                    return config.Sanitize();
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Aegis: 配置加载失败，使用默认值 ({ex.Message})");
        }
        return new AgentConfig();
    }

    /// 校验并修正字段（与 Python load_reporting_config 的约束保持一致）。
    public AgentConfig Sanitize()
    {
        ScanIntervalSeconds = Math.Max(60, ScanIntervalSeconds);
        QueueLimit = Math.Clamp(QueueLimit, 10, 10_000);
        // TODO: 校验 CollectorUrl 必须为 https、无 query/fragment、长度 <= 2048。
        // TODO: 校验 Token/Secret 长度 32...4096 且互不相等，否则清空上报配置。
        return this;
    }

    /// 保存配置（管理员权限目录，建议配合 ACL 限制读取）。
    public void Save(string? path = null)
    {
        path ??= DefaultConfigFile;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
        // TODO: 通过 DirectorySecurity 将 config.json ACL 收紧为 SYSTEM/Administrators 只读。
    }
}
