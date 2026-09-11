using System.Text.Json.Serialization;

namespace AegisAgent.Models;

/* ─── Report Schema (aegis.report/v1) ───────────────────── */

public record Report(
    [property: JsonPropertyName("schema")] string Schema,
    [property: JsonPropertyName("agent_version")] string AgentVersion,
    [property: JsonPropertyName("policy_version")] string PolicyVersion,
    [property: JsonPropertyName("device_id")] string DeviceId,
    [property: JsonPropertyName("scanned_at")] long ScannedAt,
    [property: JsonPropertyName("summary")] Summary Summary,
    [property: JsonPropertyName("findings")] List<Finding> Findings,
    [property: JsonPropertyName("inventory")] List<Dictionary<string, string>>? Inventory = null
);

public record Summary(
    [property: JsonPropertyName("critical")] int Critical,
    [property: JsonPropertyName("high")] int High,
    [property: JsonPropertyName("medium")] int Medium,
    [property: JsonPropertyName("low")] int Low
);

public record Finding(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("evidence")] string? Evidence = null
);

/* ─── Policy ────────────────────────────────────────────── */

public class Policy
{
    [JsonPropertyName("version")] public string Version { get; set; } = "0.0.0";
    [JsonPropertyName("rules")] public List<PolicyRule>? Rules { get; set; }
    [JsonPropertyName("scan_interval_seconds")] public int? ScanIntervalSeconds { get; set; }
    [JsonPropertyName("exclusions")] public List<string>? Exclusions { get; set; }
}

public class PolicyRule
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("description")] public string? Description { get; set; }
    [JsonPropertyName("severity")] public string? Severity { get; set; }
    [JsonPropertyName("action")] public string? Action { get; set; }
}

/* ─── Config ────────────────────────────────────────────── */

public class AgentConfig
{
    public const string Version = "0.30.0";

    [JsonPropertyName("collector_url")] public string CollectorUrl { get; set; } = "http://127.0.0.1:8931";
    [JsonPropertyName("device_id")] public string DeviceId { get; set; } = $"WIN-{Environment.MachineName}";
    [JsonPropertyName("token")] public string Token { get; set; } = "";
    [JsonPropertyName("hmac_secret")] public string? HmacSecret { get; set; }
    [JsonPropertyName("scan_interval_seconds")] public int ScanIntervalSeconds { get; set; } = 3600;
    [JsonPropertyName("scan_root")] public string? ScanRoot { get; set; }

    private static string ConfigDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AegisAgent");
    private static string ConfigPath => Path.Combine(ConfigDir, "config.json");

    public static AgentConfig Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                return JsonSerializer.Deserialize<AgentConfig>(json) ?? new AgentConfig();
            }
        }
        catch { }

        // 首次运行：生成默认配置
        var config = new AgentConfig();
        Directory.CreateDirectory(ConfigDir);
        File.WriteAllText(ConfigPath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
        return config;
    }
}
